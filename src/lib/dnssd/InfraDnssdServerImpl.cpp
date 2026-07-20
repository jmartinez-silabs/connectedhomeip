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

#include "InfraDnssdServerImpl.h"

#include <algorithm>
#include <cstring>

#include <lib/dnssd/platform/Dnssd.h>
#include <lib/support/CHIPMemString.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <system/SystemPacketBuffer.h>

namespace chip {
namespace Dnssd {

using namespace chip::Dnssd::Srp;

namespace {
constexpr System::Clock::Timeout kLeaseSweepInterval = System::Clock::Seconds32(5);

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
    if (len >= outSize)
    {
        len = outSize - 1;
    }
    memcpy(out, cursor, len);
    out[len] = '\0';
}
} // namespace

CHIP_ERROR InfraDnssdServerImpl::Init(InfraDnssdServerDelegate * delegate)
{
    mDelegate = delegate;
    ChipLogProgress(Discovery, "InfraDnssdServer initialized");
    return CHIP_NO_ERROR;
}

void InfraDnssdServerImpl::Shutdown()
{
    (void) Stop();
    mDelegate = nullptr;
    for (HostRecord & host : mHosts)
    {
        host.inUse = false;
    }
    for (ServiceRecord & svc : mServices)
    {
        svc.inUse = false;
    }
    ChipLogProgress(Discovery, "InfraDnssdServer shut down");
}

CHIP_ERROR InfraDnssdServerImpl::Start(uint16_t port)
{
    VerifyOrReturnError(!mRunning, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(mEndPointManager != nullptr, CHIP_ERROR_INCORRECT_STATE);

    mListenPort = (port != 0) ? port : kDefaultSrpServerPort;

    ReturnErrorOnFailure(mEndPointManager->NewEndPoint(mUdpEndPoint));
    CHIP_ERROR err = mUdpEndPoint->Bind(Inet::IPAddressType::kIPv6, Inet::IPAddress::Any, mListenPort);
    if (err != CHIP_NO_ERROR)
    {
        mUdpEndPoint = nullptr;
        ChipLogError(Discovery, "InfraDnssdServer: failed to bind port %u: %" CHIP_ERROR_FORMAT, mListenPort, err.Format());
        return err;
    }
    ReturnErrorOnFailure(mUdpEndPoint->Listen(OnUdpMessageReceived, OnUdpReceiveError, this));

    mRunning = true;
    ScheduleSweep();
    ChipLogProgress(Discovery, "InfraDnssdServer listening on UDP port %u", mListenPort);
    return CHIP_NO_ERROR;
}

CHIP_ERROR InfraDnssdServerImpl::Stop()
{
    if (mSweepScheduled && mEndPointManager != nullptr)
    {
        mEndPointManager->SystemLayer().CancelTimer(OnLeaseSweepTimer, this);
        mSweepScheduled = false;
    }
    if (!mUdpEndPoint.IsNull())
    {
        mUdpEndPoint->Close();
        mUdpEndPoint = nullptr;
    }
    mRunning = false;
    return CHIP_NO_ERROR;
}

CHIP_ERROR InfraDnssdServerImpl::SetAdvertiseInfraFlag(bool enable)
{
    mAdvertiseInfraFlag = enable;
    // Wiring the flag into the platform's IPv6 RA output is handled by the
    // Discovery Proxy integration (platform RA hook).
    ChipLogProgress(Discovery, "InfraDnssdServer: advertise infrastructure RA flag = %s", enable ? "true" : "false");
    return CHIP_NO_ERROR;
}

uint16_t InfraDnssdServerImpl::GetRegisteredServiceCount() const
{
    uint16_t count = 0;
    for (const ServiceRecord & svc : mServices)
    {
        if (svc.inUse)
        {
            count++;
        }
    }
    return count;
}

const InfraDnssdServerImpl::HostRecord * InfraDnssdServerImpl::FindHost(const char * hostName) const
{
    for (const HostRecord & host : mHosts)
    {
        if (host.inUse && strcmp(host.hostName, hostName) == 0)
        {
            return &host;
        }
    }
    return nullptr;
}

InfraDnssdServerImpl::HostRecord * InfraDnssdServerImpl::FindHostMutable(const char * hostName)
{
    for (HostRecord & host : mHosts)
    {
        if (host.inUse && strcmp(host.hostName, hostName) == 0)
        {
            return &host;
        }
    }
    return nullptr;
}

InfraDnssdServerImpl::HostRecord * InfraDnssdServerImpl::AllocateHost()
{
    for (HostRecord & host : mHosts)
    {
        if (!host.inUse)
        {
            return &host;
        }
    }
    return nullptr;
}

InfraDnssdServerImpl::ServiceRecord * InfraDnssdServerImpl::FindService(const char * instanceName)
{
    for (ServiceRecord & svc : mServices)
    {
        if (svc.inUse && strcmp(svc.instanceName, instanceName) == 0)
        {
            return &svc;
        }
    }
    return nullptr;
}

InfraDnssdServerImpl::ServiceRecord * InfraDnssdServerImpl::AllocateService()
{
    for (ServiceRecord & svc : mServices)
    {
        if (!svc.inUse)
        {
            return &svc;
        }
    }
    return nullptr;
}

void InfraDnssdServerImpl::RemoveServicesForHost(const char * hostName)
{
    for (ServiceRecord & svc : mServices)
    {
        if (svc.inUse && strcmp(svc.hostName, hostName) == 0)
        {
            if (mDelegate != nullptr)
            {
                mDelegate->OnServiceRemoved(svc.instanceName, svc.serviceType);
            }
            svc.inUse = false;
        }
    }
}

void InfraDnssdServerImpl::OnUdpMessageReceived(Inet::UDPEndPoint * endPoint, System::PacketBufferHandle && msg,
                                                const Inet::IPPacketInfo * pktInfo)
{
    auto * self = (endPoint != nullptr) ? static_cast<InfraDnssdServerImpl *>(endPoint->mAppState) : nullptr;
    VerifyOrReturn(self != nullptr && !msg.IsNull() && pktInfo != nullptr);
    self->HandleMessage(msg->Start(), msg->DataLength(), pktInfo);
}

void InfraDnssdServerImpl::OnUdpReceiveError(Inet::UDPEndPoint * endPoint, CHIP_ERROR error, const Inet::IPPacketInfo * pktInfo)
{
    ChipLogError(Discovery, "InfraDnssdServer: UDP receive error: %" CHIP_ERROR_FORMAT, error.Format());
}

void InfraDnssdServerImpl::HandleMessage(const uint8_t * message, size_t length, const Inet::IPPacketInfo * pktInfo)
{
    Header header;
    DnsReader reader(message, length);
    if (reader.ReadHeader(header) != CHIP_NO_ERROR)
    {
        return;
    }

    if (header.Opcode() == kOpcodeUpdate)
    {
        HandleUpdate(message, length, pktInfo);
    }
    else if (header.Opcode() == kOpcodeQuery)
    {
        HandleQuery(message, length, pktInfo);
    }
}

void InfraDnssdServerImpl::HandleUpdate(const uint8_t * message, size_t length, const Inet::IPPacketInfo * pktInfo)
{
    Header header;
    {
        DnsReader reader(message, length);
        if (reader.ReadHeader(header) != CHIP_NO_ERROR)
        {
            return;
        }
    }

    uint32_t grantedLease    = 0;
    uint32_t grantedKeyLease = 0;
    ResponseCode rcode       = ProcessUpdate(message, length, pktInfo->SrcAddress, &grantedLease, &grantedKeyLease);
    SendResponse(pktInfo, header.id, rcode, grantedLease, grantedKeyLease);
}

void InfraDnssdServerImpl::HandleQuery(const uint8_t * message, size_t length, const Inet::IPPacketInfo * pktInfo)
{
    uint8_t response[512];
    size_t responseLen = 0;
    ResponseCode rcode = BuildQueryResponse(message, length, response, sizeof(response), responseLen);
    // Drop malformed queries silently; only reply when a response was encoded.
    if (rcode == ResponseCode::kNoError && responseLen > 0)
    {
        SendRawResponse(pktInfo, response, responseLen);
    }
}

Srp::ResponseCode InfraDnssdServerImpl::ProcessUpdate(const uint8_t * message, size_t length,
                                                      const Inet::IPAddress & clientAddress, uint32_t * grantedLease,
                                                      uint32_t * grantedKeyLease)
{
    ParsedUpdate update;
    if (ParseUpdate(message, length, update) != CHIP_NO_ERROR)
    {
        return ResponseCode::kFormErr;
    }

    // Determine the key to authenticate with: the update's own KEY (registration)
    // or the stored key for the host (removal / re-registration).
    const uint8_t * verifyKey = nullptr;
    if (update.hasKey)
    {
        verifyKey = update.publicKey;
    }
    else if (update.hasHost)
    {
        const HostRecord * host = FindHost(update.hostName);
        if (host != nullptr)
        {
            verifyKey = host->publicKey;
        }
    }

    if (verifyKey == nullptr)
    {
        return ResponseCode::kRefused;
    }

    if (VerifySig0(message, length, ByteSpan(verifyKey, kSrpPublicKeyRawSize)) != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssdServer: SIG(0) verification failed");
        return ResponseCode::kNotAuth;
    }

    uint32_t lease    = 0;
    uint32_t keyLease = 0;
    ResponseCode rcode = ApplyUpdate(update, clientAddress, lease, keyLease);
    if (grantedLease != nullptr)
    {
        *grantedLease = lease;
    }
    if (grantedKeyLease != nullptr)
    {
        *grantedKeyLease = keyLease;
    }
    return rcode;
}

Srp::ResponseCode InfraDnssdServerImpl::ApplyUpdate(const ParsedUpdate & update, const Inet::IPAddress & clientAddress,
                                                    uint32_t & grantedLease, uint32_t & grantedKeyLease)
{
    VerifyOrReturnValue(update.hasHost, ResponseCode::kFormErr);

    // First-come first-served: an existing host may only be updated by the same key.
    HostRecord * host = FindHostMutable(update.hostName);
    if (host != nullptr && update.hasKey && memcmp(host->publicKey, update.publicKey, kSrpPublicKeyRawSize) != 0)
    {
        return ResponseCode::kNotAuth;
    }

    if (update.hostRemoval)
    {
        RemoveServicesForHost(update.hostName);
        if (host != nullptr)
        {
            host->inUse = false;
        }
        ChipLogProgress(Discovery, "InfraDnssdServer: removed host %s", update.hostName);
        RepublishAllViaMdns();
        return ResponseCode::kNoError;
    }

    // Clamp the requested lease to the server's policy and report the granted
    // values back to the caller so they can be echoed to the client.
    grantedLease    = std::min(update.lease, kMaxGrantedLeaseSeconds);
    grantedKeyLease = std::min(update.keyLease != 0 ? update.keyLease : kMaxGrantedKeyLeaseSeconds, kMaxGrantedKeyLeaseSeconds);

    System::Clock::Timestamp now       = System::SystemClock().GetMonotonicTimestamp();
    System::Clock::Timestamp expiresAt = now + System::Clock::Seconds32(grantedLease);

    if (host == nullptr)
    {
        host = AllocateHost();
        VerifyOrReturnValue(host != nullptr, ResponseCode::kServFail);
        host->inUse = true;
        Platform::CopyString(host->hostName, update.hostName);
    }
    if (update.hasKey)
    {
        memcpy(host->publicKey, update.publicKey, kSrpPublicKeyRawSize);
    }
    host->addressCount = 0;
    for (size_t i = 0; i < update.addressCount && i < kMaxParsedAddresses; i++)
    {
        host->addresses[host->addressCount++] = update.addresses[i];
    }
    host->clientAddress = clientAddress;
    host->expiresAt     = expiresAt;

    // Incremental (upsert/delete) per service so a single UPDATE can add some
    // services and remove others, matching a standards-compliant SRP client.
    // Services not mentioned in this UPDATE are left untouched (until their
    // lease expires), rather than being wiped as in a full-replace.
    bool changed = false;
    for (size_t i = 0; i < update.serviceCount; i++)
    {
        const ParsedService & parsed = update.services[i];
        if (parsed.isDelete)
        {
            ServiceRecord * svc = FindService(parsed.instanceName);
            if (svc != nullptr)
            {
                if (mDelegate != nullptr)
                {
                    mDelegate->OnServiceRemoved(svc->instanceName, svc->serviceType);
                }
                svc->inUse = false;
                changed    = true;
            }
            continue;
        }

        ServiceRecord * svc = FindService(parsed.instanceName);
        if (svc == nullptr)
        {
            svc = AllocateService();
        }
        if (svc == nullptr)
        {
            ChipLogError(Discovery, "InfraDnssdServer: service table full");
            return ResponseCode::kServFail;
        }
        svc->inUse = true;
        Platform::CopyString(svc->instanceName, parsed.instanceName);
        Platform::CopyString(svc->serviceType, parsed.serviceType);
        Platform::CopyString(svc->hostName, update.hostName);
        svc->port      = parsed.port;
        svc->txtLen    = static_cast<uint16_t>(std::min<size_t>(parsed.txtLen, sizeof(svc->txt)));
        memcpy(svc->txt, parsed.txt, svc->txtLen);
        svc->expiresAt = expiresAt;
        changed        = true;

        ChipLogProgress(Discovery, "InfraDnssdServer: registered %s (%s) port %u", svc->instanceName, svc->serviceType,
                        svc->port);
        if (mDelegate != nullptr)
        {
            mDelegate->OnServiceRegistered(clientAddress, update.hostName, svc->instanceName, svc->serviceType, svc->port);
        }
    }

    if (changed)
    {
        RepublishAllViaMdns();
    }

    return ResponseCode::kNoError;
}

void InfraDnssdServerImpl::PublishViaMdns(const ServiceRecord & service)
{
    if (!mAdvertisingProxyEnabled)
    {
        return;
    }

    DnssdService out = {};
    ExtractLabel(service.instanceName, 0, out.mName, sizeof(out.mName));
    ExtractLabel(service.hostName, 0, out.mHostName, sizeof(out.mHostName));
    ExtractLabel(service.serviceType, 0, out.mType, sizeof(out.mType));

    char protocol[8];
    ExtractLabel(service.serviceType, 1, protocol, sizeof(protocol));
    out.mProtocol    = (strcmp(protocol, "_udp") == 0) ? DnssdServiceProtocol::kDnssdProtocolUdp
                                                       : DnssdServiceProtocol::kDnssdProtocolTcp;
    out.mPort        = service.port;
    out.mInterface   = Inet::InterfaceId::Null();
    out.mAddressType = Inet::IPAddressType::kIPv6;

    // Parse the stored TXT RDATA (length-prefixed strings) into TextEntry items.
    static constexpr size_t kMaxEntries = 16;
    TextEntry entries[kMaxEntries];
    char keyStorage[kMaxEntries][kMaxParsedTxtSize];
    size_t entryCount = 0;
    size_t offset     = 0;
    while (offset < service.txtLen && entryCount < kMaxEntries)
    {
        uint8_t len = service.txt[offset++];
        if (len == 0 || offset + len > service.txtLen)
        {
            break;
        }
        const uint8_t * str = service.txt + offset;
        offset += len;

        // Split "key=value".
        size_t eq = 0;
        while (eq < len && str[eq] != '=')
        {
            eq++;
        }
        size_t keyLen = std::min<size_t>(eq, kMaxParsedTxtSize - 1);
        memcpy(keyStorage[entryCount], str, keyLen);
        keyStorage[entryCount][keyLen] = '\0';
        entries[entryCount].mKey       = keyStorage[entryCount];
        if (eq < len)
        {
            entries[entryCount].mData     = str + eq + 1;
            entries[entryCount].mDataSize = len - eq - 1;
        }
        else
        {
            entries[entryCount].mData     = nullptr;
            entries[entryCount].mDataSize = 0;
        }
        entryCount++;
    }
    out.mTextEntries = (entryCount > 0) ? entries : nullptr;
    out.mTextEntrySize = entryCount;

    CHIP_ERROR err = ChipDnssdPublishService(&out);
    if (err == CHIP_NO_ERROR)
    {
        err = ChipDnssdFinalizeServiceUpdate();
    }
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssdServer: advertising proxy publish failed: %" CHIP_ERROR_FORMAT, err.Format());
    }
}

void InfraDnssdServerImpl::RepublishAllViaMdns()
{
    if (!mAdvertisingProxyEnabled)
    {
        return;
    }

    // The platform advertiser publishes an aggregate record set, so withdraw
    // everything and re-publish the services that are still active.
    CHIP_ERROR err = ChipDnssdRemoveServices();
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssdServer: advertising proxy remove failed: %" CHIP_ERROR_FORMAT, err.Format());
    }
    for (const ServiceRecord & svc : mServices)
    {
        if (svc.inUse)
        {
            PublishViaMdns(svc);
        }
    }
}

namespace {
// Remaining lease as a DNS TTL (seconds), clamped to a sane maximum.
uint32_t RemainingTtl(System::Clock::Timestamp expiresAt, System::Clock::Timestamp now)
{
    if (expiresAt <= now)
    {
        return 0;
    }
    uint64_t seconds = (expiresAt - now).count() / 1000;
    return static_cast<uint32_t>(std::min<uint64_t>(seconds, 7200));
}

// Write a TXT record from raw length-prefixed RDATA. An empty TXT is encoded as
// a single empty character-string (0x00), per RFC 6763.
CHIP_ERROR PutRawTxt(DnsWriter & writer, const char * name, uint32_t ttl, const uint8_t * txt, uint16_t txtLen)
{
    ReturnErrorOnFailure(writer.StartRecord(name, RecordType::kTxt, RecordClass::kIn, ttl));
    if (txtLen == 0)
    {
        const uint8_t empty = 0;
        ReturnErrorOnFailure(writer.PutBytes(&empty, 1));
    }
    else
    {
        ReturnErrorOnFailure(writer.PutBytes(txt, txtLen));
    }
    return writer.FinishRecord();
}
} // namespace

Srp::ResponseCode InfraDnssdServerImpl::BuildQueryResponse(const uint8_t * message, size_t length, uint8_t * out, size_t outSize,
                                                           size_t & outLen)
{
    outLen = 0;

    Header header;
    DnsReader reader(message, length);
    VerifyOrReturnValue(reader.ReadHeader(header) == CHIP_NO_ERROR, ResponseCode::kFormErr);
    VerifyOrReturnValue(header.qdcount >= 1, ResponseCode::kFormErr);

    char qname[Srp::kMaxDottedNameSize];
    uint16_t qtypeRaw  = 0;
    uint16_t qclassRaw = 0;
    VerifyOrReturnValue(reader.ReadName(qname, sizeof(qname)) == CHIP_NO_ERROR, ResponseCode::kFormErr);
    VerifyOrReturnValue(reader.ReadU16(qtypeRaw) == CHIP_NO_ERROR, ResponseCode::kFormErr);
    VerifyOrReturnValue(reader.ReadU16(qclassRaw) == CHIP_NO_ERROR, ResponseCode::kFormErr);

    const auto qtype = static_cast<RecordType>(qtypeRaw);
    const bool wantPtr  = (qtype == RecordType::kPtr || qtype == RecordType::kAny);
    const bool wantSrv  = (qtype == RecordType::kSrv || qtype == RecordType::kAny);
    const bool wantTxt  = (qtype == RecordType::kTxt || qtype == RecordType::kAny);
    const bool wantAaaa = (qtype == RecordType::kAaaa || qtype == RecordType::kAny);

    System::Clock::Timestamp now = System::SystemClock().GetMonotonicTimestamp();

    DnsWriter writer(out, outSize);
    VerifyOrReturnValue(writer.PutHeader(header.id, MakeFlags(kOpcodeQuery, /*response=*/true, ResponseCode::kNoError),
                                         /*qdcount=*/1, 0, 0, 0) == CHIP_NO_ERROR,
                        ResponseCode::kServFail);
    VerifyOrReturnValue(writer.PutQuestion(qname, qtype, RecordClass::kIn) == CHIP_NO_ERROR, ResponseCode::kServFail);

    uint16_t ancount = 0;
    uint16_t arcount = 0;

    // PTR browse: qname is a service type; answer with matching instances and
    // include their SRV/TXT/AAAA in the additional section.
    //
    // DNS wire order requires the entire answer section before the additional
    // section, so all matching PTR records are written first, then a second
    // pass emits the SRV/TXT/AAAA records. Interleaving per service would place
    // additional records inside the answer section and cause a client reading
    // the first ancount records to miss PTRs for later services.
    if (wantPtr)
    {
        for (const ServiceRecord & svc : mServices)
        {
            if (!svc.inUse || strcmp(svc.serviceType, qname) != 0)
            {
                continue;
            }
            uint32_t ttl = RemainingTtl(svc.expiresAt, now);
            if (writer.PutPtr(svc.serviceType, RecordClass::kIn, ttl, svc.instanceName) != CHIP_NO_ERROR)
            {
                break;
            }
            ancount++;
        }

        for (const ServiceRecord & svc : mServices)
        {
            if (!svc.inUse || strcmp(svc.serviceType, qname) != 0)
            {
                continue;
            }
            uint32_t ttl = RemainingTtl(svc.expiresAt, now);
            if (writer.PutSrv(svc.instanceName, RecordClass::kIn, ttl, 0, 0, svc.port, svc.hostName) == CHIP_NO_ERROR)
            {
                arcount++;
            }
            if (PutRawTxt(writer, svc.instanceName, ttl, svc.txt, svc.txtLen) == CHIP_NO_ERROR)
            {
                arcount++;
            }
            const HostRecord * host = FindHost(svc.hostName);
            if (host != nullptr)
            {
                for (size_t i = 0; i < host->addressCount; i++)
                {
                    if (writer.PutAaaa(host->hostName, RecordClass::kIn, ttl, host->addresses[i]) == CHIP_NO_ERROR)
                    {
                        arcount++;
                    }
                }
            }
        }
    }

    // SRV/TXT resolve: qname is a service instance name.
    if (wantSrv || wantTxt)
    {
        for (const ServiceRecord & svc : mServices)
        {
            if (!svc.inUse || strcmp(svc.instanceName, qname) != 0)
            {
                continue;
            }
            uint32_t ttl = RemainingTtl(svc.expiresAt, now);
            if (wantSrv &&
                writer.PutSrv(svc.instanceName, RecordClass::kIn, ttl, 0, 0, svc.port, svc.hostName) == CHIP_NO_ERROR)
            {
                ancount++;
            }
            if (wantTxt)
            {
                if (PutRawTxt(writer, svc.instanceName, ttl, svc.txt, svc.txtLen) == CHIP_NO_ERROR)
                {
                    ancount++;
                }
            }
            else if (wantSrv)
            {
                // Include TXT in the additional section so an SRV resolve carries
                // the service's TXT record, per typical DNS-SD resolve behavior.
                if (PutRawTxt(writer, svc.instanceName, ttl, svc.txt, svc.txtLen) == CHIP_NO_ERROR)
                {
                    arcount++;
                }
            }
            const HostRecord * host = FindHost(svc.hostName);
            if (host != nullptr)
            {
                for (size_t i = 0; i < host->addressCount; i++)
                {
                    if (writer.PutAaaa(host->hostName, RecordClass::kIn, ttl, host->addresses[i]) == CHIP_NO_ERROR)
                    {
                        arcount++;
                    }
                }
            }
        }
    }

    // AAAA resolve: qname is a host name.
    if (wantAaaa)
    {
        const HostRecord * host = FindHost(qname);
        if (host != nullptr)
        {
            uint32_t ttl = RemainingTtl(host->expiresAt, now);
            for (size_t i = 0; i < host->addressCount; i++)
            {
                if (writer.PutAaaa(host->hostName, RecordClass::kIn, ttl, host->addresses[i]) == CHIP_NO_ERROR)
                {
                    ancount++;
                }
            }
        }
    }

    VerifyOrReturnValue(writer.Ok(), ResponseCode::kServFail);
    writer.PatchHeaderCounts(1, ancount, 0, arcount);
    outLen = writer.Length();
    return ResponseCode::kNoError;
}

void InfraDnssdServerImpl::SendResponse(const Inet::IPPacketInfo * pktInfo, uint16_t transactionId, ResponseCode rcode,
                                        uint32_t grantedLease, uint32_t grantedKeyLease)
{
    VerifyOrReturn(pktInfo != nullptr && !mUdpEndPoint.IsNull());

    // Header plus an optional OPT record echoing the granted lease.
    uint8_t buffer[kDnsHeaderSize + 32];
    DnsWriter writer(buffer, sizeof(buffer));
    const bool echoLease = (rcode == ResponseCode::kNoError) && (grantedLease != 0 || grantedKeyLease != 0);
    if (writer.PutHeader(transactionId, MakeFlags(kOpcodeUpdate, /*response=*/true, rcode), 0, 0, 0, echoLease ? 1 : 0) !=
        CHIP_NO_ERROR)
    {
        return;
    }
    if (echoLease && PutUpdateLeaseOption(writer, grantedLease, grantedKeyLease) != CHIP_NO_ERROR)
    {
        return;
    }

    System::PacketBufferHandle response = System::PacketBufferHandle::NewWithData(writer.Data(), writer.Length());
    VerifyOrReturn(!response.IsNull());
    CHIP_ERROR err = mUdpEndPoint->SendTo(pktInfo->SrcAddress, pktInfo->SrcPort, std::move(response), pktInfo->Interface);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssdServer: failed to send response: %" CHIP_ERROR_FORMAT, err.Format());
    }
}

void InfraDnssdServerImpl::SendRawResponse(const Inet::IPPacketInfo * pktInfo, const uint8_t * data, size_t length)
{
    VerifyOrReturn(pktInfo != nullptr && !mUdpEndPoint.IsNull() && data != nullptr && length > 0);

    System::PacketBufferHandle response = System::PacketBufferHandle::NewWithData(data, length);
    VerifyOrReturn(!response.IsNull());
    CHIP_ERROR err = mUdpEndPoint->SendTo(pktInfo->SrcAddress, pktInfo->SrcPort, std::move(response), pktInfo->Interface);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssdServer: failed to send query response: %" CHIP_ERROR_FORMAT, err.Format());
    }
}

void InfraDnssdServerImpl::SweepExpired()
{
    System::Clock::Timestamp now = System::SystemClock().GetMonotonicTimestamp();
    bool anyExpired              = false;
    for (ServiceRecord & svc : mServices)
    {
        if (svc.inUse && svc.expiresAt <= now)
        {
            ChipLogProgress(Discovery, "InfraDnssdServer: lease expired for %s", svc.instanceName);
            if (mDelegate != nullptr)
            {
                mDelegate->OnServiceRemoved(svc.instanceName, svc.serviceType);
            }
            svc.inUse  = false;
            anyExpired = true;
        }
    }
    for (HostRecord & host : mHosts)
    {
        if (host.inUse && host.expiresAt <= now)
        {
            host.inUse = false;
        }
    }
    if (anyExpired)
    {
        RepublishAllViaMdns();
    }
}

void InfraDnssdServerImpl::ScheduleSweep()
{
    VerifyOrReturn(mEndPointManager != nullptr && mRunning);
    CHIP_ERROR err = mEndPointManager->SystemLayer().StartTimer(kLeaseSweepInterval, OnLeaseSweepTimer, this);
    if (err == CHIP_NO_ERROR)
    {
        mSweepScheduled = true;
    }
}

void InfraDnssdServerImpl::OnLeaseSweepTimer(System::Layer * layer, void * context)
{
    auto * self = static_cast<InfraDnssdServerImpl *>(context);
    VerifyOrReturn(self != nullptr);
    self->mSweepScheduled = false;
    if (!self->mRunning)
    {
        return;
    }
    self->SweepExpired();
    self->ScheduleSweep();
}

} // namespace Dnssd
} // namespace chip
