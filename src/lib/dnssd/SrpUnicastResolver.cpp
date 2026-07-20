/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "SrpUnicastResolver.h"

#include <algorithm>
#include <cstring>

#include <lib/dnssd/SrpDnsMessage.h>
#include <lib/dnssd/SrpUpdate.h>
#include <lib/support/CHIPMemString.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <system/SystemClock.h>
#include <system/SystemLayer.h>
#include <system/SystemPacketBuffer.h>

namespace chip {
namespace Dnssd {
namespace Srp {

namespace {

constexpr size_t kMaxConcurrentQueries        = 4;
constexpr size_t kMaxBrowseResults            = 8;
constexpr size_t kMaxResolveTextEntries       = 16;
constexpr System::Clock::Timeout kQueryTimeout = System::Clock::Seconds16(3);

struct Query;
void OnQueryTimeout(System::Layer * layer, void * context);
void ReleaseQuery(Query * query);

// Copy the Nth label (0-based) of a dotted name into out (null-terminated).
void ExtractLabel(const char * name, size_t index, char * out, size_t outSize)
{
    const char * cursor = name;
    for (size_t i = 0; i < index; i++)
    {
        const char * dot = strchr(cursor, '.');
        if (dot == nullptr)
        {
            out[0] = '\0';
            return;
        }
        cursor = dot + 1;
    }
    const char * dot = strchr(cursor, '.');
    size_t len       = (dot != nullptr) ? static_cast<size_t>(dot - cursor) : strlen(cursor);
    len              = std::min(len, outSize - 1);
    memcpy(out, cursor, len);
    out[len] = '\0';
}

const char * ProtocolLabel(DnssdServiceProtocol protocol)
{
    return (protocol == DnssdServiceProtocol::kDnssdProtocolUdp) ? "_udp" : "_tcp";
}

struct Query
{
    bool inUse = false;
    Inet::EndPointHandle<Inet::UDPEndPoint> endPoint;
    Inet::EndPointManager<Inet::UDPEndPoint> * manager = nullptr;

    bool isBrowse = false;
    DnssdBrowseCallback browseCallback   = nullptr;
    DnssdResolveCallback resolveCallback = nullptr;
    void * context                       = nullptr;

    // Saved request details used to reconstruct DnssdService results.
    char serviceType[kDnssdTypeMaxSize + 1] = ""; // e.g. "_matter._tcp"
    char instanceLabel[Common::kInstanceNameMaxLength + 1] = "";
    DnssdServiceProtocol protocol = DnssdServiceProtocol::kDnssdProtocolUnknown;
    Inet::IPAddressType addressType = Inet::IPAddressType::kIPv6;
    Inet::InterfaceId interface     = Inet::InterfaceId::Null();
};

Query sQueries[kMaxConcurrentQueries];

Query * AllocateQuery()
{
    for (Query & q : sQueries)
    {
        if (!q.inUse)
        {
            return &q;
        }
    }
    return nullptr;
}

void ReleaseQuery(Query * query)
{
    VerifyOrReturn(query != nullptr && query->inUse);
    if (query->manager != nullptr)
    {
        query->manager->SystemLayer().CancelTimer(OnQueryTimeout, query);
    }
    if (!query->endPoint.IsNull())
    {
        query->endPoint->Close();
        query->endPoint = nullptr;
    }
    query->inUse = false;
}

void DispatchBrowseError(Query * query, CHIP_ERROR error)
{
    if (query->browseCallback != nullptr)
    {
        query->browseCallback(query->context, nullptr, 0, /*finalBrowse=*/true, error);
    }
    ReleaseQuery(query);
}

void DispatchResolveError(Query * query, CHIP_ERROR error)
{
    if (query->resolveCallback != nullptr)
    {
        query->resolveCallback(query->context, nullptr, Span<Inet::IPAddress>(), error);
    }
    ReleaseQuery(query);
}

void HandleBrowseResponse(Query * query, const uint8_t * message, size_t length)
{
    DnsReader reader(message, length);
    Header header;
    if (reader.ReadHeader(header) != CHIP_NO_ERROR)
    {
        DispatchBrowseError(query, CHIP_ERROR_INVALID_MESSAGE_LENGTH);
        return;
    }
    for (uint16_t i = 0; i < header.qdcount; i++)
    {
        if (reader.SkipQuestion() != CHIP_NO_ERROR)
        {
            DispatchBrowseError(query, CHIP_ERROR_INVALID_MESSAGE_LENGTH);
            return;
        }
    }

    DnssdService results[kMaxBrowseResults];
    size_t resultCount = 0;
    for (uint16_t i = 0; i < header.ancount && resultCount < kMaxBrowseResults; i++)
    {
        DnsReader::RecordHeader rr;
        if (reader.ReadRecordHeader(rr) != CHIP_NO_ERROR)
        {
            break;
        }
        if (rr.type == RecordType::kPtr)
        {
            char target[kMaxDottedNameSize];
            if (reader.ReadPtr(target, sizeof(target)) == CHIP_NO_ERROR)
            {
                DnssdService & svc = results[resultCount];
                svc                = DnssdService{};
                ExtractLabel(target, 0, svc.mName, sizeof(svc.mName));
                Platform::CopyString(svc.mType, query->serviceType);
                svc.mProtocol    = query->protocol;
                svc.mAddressType = query->addressType;
                svc.mInterface   = query->interface;
                resultCount++;
            }
        }
        else if (reader.SkipRecordData(rr) != CHIP_NO_ERROR)
        {
            break;
        }
    }

    if (query->browseCallback != nullptr)
    {
        query->browseCallback(query->context, resultCount > 0 ? results : nullptr, resultCount, /*finalBrowse=*/true,
                              CHIP_NO_ERROR);
    }
    ReleaseQuery(query);
}

void HandleResolveResponse(Query * query, const uint8_t * message, size_t length)
{
    DnsReader reader(message, length);
    Header header;
    if (reader.ReadHeader(header) != CHIP_NO_ERROR)
    {
        DispatchResolveError(query, CHIP_ERROR_INVALID_MESSAGE_LENGTH);
        return;
    }
    for (uint16_t i = 0; i < header.qdcount; i++)
    {
        if (reader.SkipQuestion() != CHIP_NO_ERROR)
        {
            DispatchResolveError(query, CHIP_ERROR_INVALID_MESSAGE_LENGTH);
            return;
        }
    }

    DnssdService result = {};
    Platform::CopyString(result.mName, query->instanceLabel);
    Platform::CopyString(result.mType, query->serviceType);
    result.mProtocol    = query->protocol;
    result.mAddressType = query->addressType;
    result.mInterface   = query->interface;

    Inet::IPAddress addresses[kMaxParsedAddresses];
    size_t addressCount = 0;

    TextEntry textEntries[kMaxResolveTextEntries];
    char textKeys[kMaxResolveTextEntries][kMaxParsedTxtSize];
    uint8_t textRdata[kMaxParsedTxtSize];
    size_t textEntryCount = 0;
    bool haveSrv          = false;

    // DNS wire order is Question, Answer, Authority, Additional. SRV/TXT are
    // typically in Answer; AAAA host addresses are typically in Additional.
    // Authority (nscount) must be skipped or the additional section is never reached.
    auto consumeResourceRecord = [&](const DnsReader::RecordHeader & rr) -> CHIP_ERROR {
        if (rr.type == RecordType::kSrv)
        {
            uint16_t priority, weight, port;
            char target[kMaxDottedNameSize];
            if (reader.ReadSrv(priority, weight, port, target, sizeof(target)) == CHIP_NO_ERROR)
            {
                result.mPort = port;
                ExtractLabel(target, 0, result.mHostName, sizeof(result.mHostName));
                haveSrv = true;
            }
            return CHIP_NO_ERROR;
        }
        if (rr.type == RecordType::kTxt && textEntryCount == 0)
        {
            uint16_t rdlen = std::min<uint16_t>(rr.rdlength, static_cast<uint16_t>(sizeof(textRdata)));
            if (reader.ReadBytes(textRdata, rdlen) == CHIP_NO_ERROR)
            {
                size_t offset = 0;
                while (offset < rdlen && textEntryCount < kMaxResolveTextEntries)
                {
                    uint8_t entryLen = textRdata[offset++];
                    if (entryLen == 0 || offset + entryLen > rdlen)
                    {
                        break;
                    }
                    const uint8_t * str = textRdata + offset;
                    offset += entryLen;
                    size_t eq = 0;
                    while (eq < entryLen && str[eq] != '=')
                    {
                        eq++;
                    }
                    size_t keyLen = std::min<size_t>(eq, kMaxParsedTxtSize - 1);
                    memcpy(textKeys[textEntryCount], str, keyLen);
                    textKeys[textEntryCount][keyLen] = '\0';
                    textEntries[textEntryCount].mKey = textKeys[textEntryCount];
                    if (eq < entryLen)
                    {
                        textEntries[textEntryCount].mData     = str + eq + 1;
                        textEntries[textEntryCount].mDataSize = entryLen - eq - 1;
                    }
                    else
                    {
                        textEntries[textEntryCount].mData     = nullptr;
                        textEntries[textEntryCount].mDataSize = 0;
                    }
                    textEntryCount++;
                }
            }
            return CHIP_NO_ERROR;
        }
        if (rr.type == RecordType::kAaaa && addressCount < kMaxParsedAddresses)
        {
            Inet::IPAddress addr;
            if (reader.ReadAaaa(addr) == CHIP_NO_ERROR)
            {
                addresses[addressCount++] = addr;
            }
            return CHIP_NO_ERROR;
        }
        return reader.SkipRecordData(rr);
    };

    auto consumeSection = [&](uint16_t count, bool skipOnly) -> bool {
        for (uint16_t i = 0; i < count; i++)
        {
            DnsReader::RecordHeader rr;
            if (reader.ReadRecordHeader(rr) != CHIP_NO_ERROR)
            {
                return false;
            }
            CHIP_ERROR err = skipOnly ? reader.SkipRecordData(rr) : consumeResourceRecord(rr);
            if (err != CHIP_NO_ERROR)
            {
                return false;
            }
        }
        return true;
    };

    if (consumeSection(header.ancount, /*skipOnly=*/false) && consumeSection(header.nscount, /*skipOnly=*/true))
    {
        consumeSection(header.arcount, /*skipOnly=*/false);
    }

    if (!haveSrv)
    {
        DispatchResolveError(query, CHIP_ERROR_KEY_NOT_FOUND);
        return;
    }

    result.mTextEntries   = textEntryCount > 0 ? textEntries : nullptr;
    result.mTextEntrySize = textEntryCount;
    if (addressCount > 0)
    {
        result.mAddress.emplace(addresses[0]);
    }

    if (query->resolveCallback != nullptr)
    {
        query->resolveCallback(query->context, &result, Span<Inet::IPAddress>(addresses, addressCount), CHIP_NO_ERROR);
    }
    ReleaseQuery(query);
}

void OnQueryTimeout(System::Layer *, void * context)
{
    auto * query = static_cast<Query *>(context);
    VerifyOrReturn(query != nullptr && query->inUse);
    if (query->isBrowse)
    {
        DispatchBrowseError(query, CHIP_ERROR_TIMEOUT);
    }
    else
    {
        DispatchResolveError(query, CHIP_ERROR_TIMEOUT);
    }
}

void OnUdpMessageReceived(Inet::UDPEndPoint * endPoint, System::PacketBufferHandle && msg, const Inet::IPPacketInfo * pktInfo)
{
    auto * query = (endPoint != nullptr) ? static_cast<Query *>(endPoint->mAppState) : nullptr;
    VerifyOrReturn(query != nullptr && query->inUse && !msg.IsNull());
    if (query->isBrowse)
    {
        HandleBrowseResponse(query, msg->Start(), msg->DataLength());
    }
    else
    {
        HandleResolveResponse(query, msg->Start(), msg->DataLength());
    }
}

void OnUdpReceiveError(Inet::UDPEndPoint * endPoint, CHIP_ERROR error, const Inet::IPPacketInfo *)
{
    auto * query = (endPoint != nullptr) ? static_cast<Query *>(endPoint->mAppState) : nullptr;
    VerifyOrReturn(query != nullptr && query->inUse);
    if (query->isBrowse)
    {
        DispatchBrowseError(query, error);
    }
    else
    {
        DispatchResolveError(query, error);
    }
}

CHIP_ERROR OpenAndSend(Query * query, const Inet::IPAddress & serverAddress, uint16_t serverPort, const uint8_t * data,
                       size_t length)
{
    ReturnErrorOnFailure(query->manager->NewEndPoint(query->endPoint));
    CHIP_ERROR err = query->endPoint->Bind(Inet::IPAddressType::kIPv6, Inet::IPAddress::Any, 0);
    if (err == CHIP_NO_ERROR)
    {
        err = query->endPoint->Listen(OnUdpMessageReceived, OnUdpReceiveError, query);
    }
    if (err != CHIP_NO_ERROR)
    {
        query->endPoint = nullptr;
        return err;
    }

    System::PacketBufferHandle message = System::PacketBufferHandle::NewWithData(data, length);
    VerifyOrReturnError(!message.IsNull(), CHIP_ERROR_NO_MEMORY);
    ReturnErrorOnFailure(query->endPoint->SendTo(serverAddress, serverPort, std::move(message), query->interface));

    return query->manager->SystemLayer().StartTimer(kQueryTimeout, OnQueryTimeout, query);
}

} // namespace

CHIP_ERROR UnicastBrowse(Inet::EndPointManager<Inet::UDPEndPoint> * endPointManager, const char * type,
                         DnssdServiceProtocol protocol, Inet::IPAddressType addressType, Inet::InterfaceId interface,
                         const Inet::IPAddress & serverAddress, uint16_t serverPort, DnssdBrowseCallback callback,
                         void * context)
{
    VerifyOrReturnError(endPointManager != nullptr && type != nullptr && callback != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    Query * query = AllocateQuery();
    VerifyOrReturnError(query != nullptr, CHIP_ERROR_NO_MEMORY);

    *query                = Query{};
    query->inUse          = true;
    query->manager        = endPointManager;
    query->isBrowse       = true;
    query->browseCallback = callback;
    query->context        = context;
    query->protocol       = protocol;
    query->addressType    = addressType;
    query->interface      = interface;

    // Compose the fully-qualified service type ("_matter._tcp") and query name.
    char queryName[kMaxDottedNameSize];
    if (strstr(type, "._tcp") != nullptr || strstr(type, "._udp") != nullptr)
    {
        Platform::CopyString(query->serviceType, type);
    }
    else
    {
        snprintf(query->serviceType, sizeof(query->serviceType), "%s.%s", type, ProtocolLabel(protocol));
    }
    snprintf(queryName, sizeof(queryName), "%s.%s", query->serviceType, kUnicastDomain);

    uint8_t buffer[kMaxDottedNameSize + kDnsHeaderSize + 8];
    DnsWriter writer(buffer, sizeof(buffer));
    ReturnErrorOnFailure(writer.PutHeader(0, MakeFlags(kOpcodeQuery), /*qdcount=*/1, 0, 0, 0));
    ReturnErrorOnFailure(writer.PutQuestion(queryName, RecordType::kPtr, RecordClass::kIn));
    VerifyOrReturnError(writer.Ok(), CHIP_ERROR_BUFFER_TOO_SMALL);

    CHIP_ERROR err = OpenAndSend(query, serverAddress, serverPort, writer.Data(), writer.Length());
    if (err != CHIP_NO_ERROR)
    {
        ReleaseQuery(query);
    }
    return err;
}

CHIP_ERROR UnicastResolve(Inet::EndPointManager<Inet::UDPEndPoint> * endPointManager, const DnssdService * service,
                          Inet::InterfaceId interface, const Inet::IPAddress & serverAddress, uint16_t serverPort,
                          DnssdResolveCallback callback, void * context)
{
    VerifyOrReturnError(endPointManager != nullptr && service != nullptr && callback != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    Query * query = AllocateQuery();
    VerifyOrReturnError(query != nullptr, CHIP_ERROR_NO_MEMORY);

    *query                 = Query{};
    query->inUse           = true;
    query->manager         = endPointManager;
    query->isBrowse        = false;
    query->resolveCallback = callback;
    query->context         = context;
    query->protocol        = service->mProtocol;
    query->addressType     = service->mAddressType;
    query->interface       = interface;
    Platform::CopyString(query->instanceLabel, service->mName);

    if (strstr(service->mType, "._tcp") != nullptr || strstr(service->mType, "._udp") != nullptr)
    {
        Platform::CopyString(query->serviceType, service->mType);
    }
    else
    {
        snprintf(query->serviceType, sizeof(query->serviceType), "%s.%s", service->mType, ProtocolLabel(service->mProtocol));
    }

    char queryName[kMaxDottedNameSize];
    snprintf(queryName, sizeof(queryName), "%s.%s.%s", service->mName, query->serviceType, kUnicastDomain);

    uint8_t buffer[kMaxDottedNameSize + kDnsHeaderSize + 8];
    DnsWriter writer(buffer, sizeof(buffer));
    ReturnErrorOnFailure(writer.PutHeader(0, MakeFlags(kOpcodeQuery), /*qdcount=*/1, 0, 0, 0));
    ReturnErrorOnFailure(writer.PutQuestion(queryName, RecordType::kSrv, RecordClass::kIn));
    VerifyOrReturnError(writer.Ok(), CHIP_ERROR_BUFFER_TOO_SMALL);

    CHIP_ERROR err = OpenAndSend(query, serverAddress, serverPort, writer.Data(), writer.Length());
    if (err != CHIP_NO_ERROR)
    {
        ReleaseQuery(query);
    }
    return err;
}

} // namespace Srp
} // namespace Dnssd
} // namespace chip
