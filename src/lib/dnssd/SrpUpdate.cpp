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

#include "SrpUpdate.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <lib/support/CodeUtils.h>

namespace chip {
namespace Dnssd {
namespace Srp {

namespace {

constexpr uint32_t kHostRecordTtl = 120;
constexpr uint16_t kEdnsPayload   = 1232;

// Compose a dotted name from up to three parts into `out`.
CHIP_ERROR MakeName(char * out, size_t outSize, const char * a, const char * b = nullptr, const char * c = nullptr)
{
    int written;
    if (b == nullptr)
    {
        written = snprintf(out, outSize, "%s", a);
    }
    else if (c == nullptr)
    {
        written = snprintf(out, outSize, "%s.%s", a, b);
    }
    else
    {
        written = snprintf(out, outSize, "%s.%s.%s", a, b, c);
    }
    VerifyOrReturnError(written > 0 && static_cast<size_t>(written) < outSize, CHIP_ERROR_BUFFER_TOO_SMALL);
    return CHIP_NO_ERROR;
}

const char * ZoneOf(const UpdateParams & params)
{
    return (params.zone != nullptr) ? params.zone : kDefaultServiceZone;
}

} // namespace

CHIP_ERROR PutUpdateLeaseOption(DnsWriter & writer, uint32_t lease, uint32_t keyLease)
{
    // OPT: NAME root, TYPE OPT, CLASS = UDP payload size, TTL = extended flags (0).
    ReturnErrorOnFailure(writer.StartRecord("", RecordType::kOpt, static_cast<RecordClass>(kEdnsPayload), 0));
    ReturnErrorOnFailure(writer.PutU16(kEdnsOptionUpdateLease)); // option-code
    ReturnErrorOnFailure(writer.PutU16(8));                      // option-length: LEASE + KEY-LEASE
    ReturnErrorOnFailure(writer.PutU32(lease));
    ReturnErrorOnFailure(writer.PutU32(keyLease));
    return writer.FinishRecord();
}

CHIP_ERROR AppendSig0(DnsWriter & writer, const SrpKeyPair & keyPair, uint32_t inception, uint32_t expiration)
{
    VerifyOrReturnError(writer.Ok(), CHIP_ERROR_BUFFER_TOO_SMALL);

    uint8_t fixed[kSig0FixedRdataSize];
    size_t o        = 0;
    fixed[o++]      = 0; // type covered (hi)
    fixed[o++]      = 0; // type covered (lo)
    fixed[o++]      = kKeyAlgorithmEcdsaP256Sha256;
    fixed[o++]      = 0; // labels
    fixed[o++]      = 0; // original TTL
    fixed[o++]      = 0;
    fixed[o++]      = 0;
    fixed[o++]      = 0;
    fixed[o++]      = static_cast<uint8_t>((expiration >> 24) & 0xFF);
    fixed[o++]      = static_cast<uint8_t>((expiration >> 16) & 0xFF);
    fixed[o++]      = static_cast<uint8_t>((expiration >> 8) & 0xFF);
    fixed[o++]      = static_cast<uint8_t>(expiration & 0xFF);
    fixed[o++]      = static_cast<uint8_t>((inception >> 24) & 0xFF);
    fixed[o++]      = static_cast<uint8_t>((inception >> 16) & 0xFF);
    fixed[o++]      = static_cast<uint8_t>((inception >> 8) & 0xFF);
    fixed[o++]      = static_cast<uint8_t>(inception & 0xFF);
    uint16_t keyTag = keyPair.ComputeKeyTag();
    fixed[o++]      = static_cast<uint8_t>((keyTag >> 8) & 0xFF);
    fixed[o++]      = static_cast<uint8_t>(keyTag & 0xFF);
    fixed[o++]      = 0; // signer name: root
    VerifyOrReturnError(o == kSig0FixedRdataSize, CHIP_ERROR_INTERNAL);

    // Signature covers: SIG fixed RDATA || message-so-far (header ARCOUNT must
    // already include this SIG record).
    size_t bodyLen = writer.Length();
    uint8_t hashInput[kSig0FixedRdataSize + 2048];
    VerifyOrReturnError(bodyLen <= sizeof(hashInput) - kSig0FixedRdataSize, CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(hashInput, fixed, kSig0FixedRdataSize);
    memcpy(hashInput + kSig0FixedRdataSize, writer.Data(), bodyLen);

    uint8_t signatureBuf[kSrpSignatureRawSize];
    MutableByteSpan signature(signatureBuf);
    ReturnErrorOnFailure(keyPair.Sign(ByteSpan(hashInput, kSig0FixedRdataSize + bodyLen), signature));

    ReturnErrorOnFailure(writer.StartRecord("", RecordType::kSig, RecordClass::kAny, 0));
    ReturnErrorOnFailure(writer.PutBytes(fixed, kSig0FixedRdataSize));
    ReturnErrorOnFailure(writer.PutBytes(signature.data(), signature.size()));
    return writer.FinishRecord();
}

CHIP_ERROR VerifySig0(const uint8_t * message, size_t length, ByteSpan rawPublicKey)
{
    DnsReader reader(message, length);
    Header header;
    ReturnErrorOnFailure(reader.ReadHeader(header));

    for (uint16_t i = 0; i < header.qdcount; i++)
    {
        ReturnErrorOnFailure(reader.SkipQuestion());
    }
    uint32_t nonArCount = static_cast<uint32_t>(header.ancount) + header.nscount;
    for (uint32_t i = 0; i < nonArCount; i++)
    {
        DnsReader::RecordHeader rr;
        ReturnErrorOnFailure(reader.ReadRecordHeader(rr));
        ReturnErrorOnFailure(reader.SkipRecordData(rr));
    }

    size_t sigOwnerStart  = 0;
    size_t sigRdataOffset = 0;
    uint16_t sigRdlength  = 0;
    bool foundSig         = false;
    for (uint16_t i = 0; i < header.arcount; i++)
    {
        size_t ownerStart = reader.Offset();
        DnsReader::RecordHeader rr;
        ReturnErrorOnFailure(reader.ReadRecordHeader(rr));
        if (rr.type == RecordType::kSig)
        {
            sigOwnerStart  = ownerStart;
            sigRdataOffset = rr.rdataOffset;
            sigRdlength    = rr.rdlength;
            foundSig       = true;
        }
        ReturnErrorOnFailure(reader.SkipRecordData(rr));
    }

    VerifyOrReturnError(foundSig, CHIP_ERROR_INVALID_SIGNATURE);
    VerifyOrReturnError(sigRdlength == kSig0FixedRdataSize + kSrpSignatureRawSize, CHIP_ERROR_INVALID_SIGNATURE);

    // Reconstruct the signed data: SIG fixed RDATA || message[0 .. sigOwnerStart).
    uint8_t hashInput[kSig0FixedRdataSize + 2048];
    VerifyOrReturnError(sigOwnerStart <= sizeof(hashInput) - kSig0FixedRdataSize, CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(hashInput, message + sigRdataOffset, kSig0FixedRdataSize);
    memcpy(hashInput + kSig0FixedRdataSize, message, sigOwnerStart);

    return SrpKeyPair::Verify(rawPublicKey, ByteSpan(hashInput, kSig0FixedRdataSize + sigOwnerStart),
                              ByteSpan(message + sigRdataOffset + kSig0FixedRdataSize, kSrpSignatureRawSize));
}

namespace {

// Encode a single service as RFC 2136 delete forms (SRV + TXT RRset delete and
// the specific PTR mapping). Returns the number of update records written.
CHIP_ERROR PutServiceDelete(DnsWriter & writer, const char * zone, const char * instanceName, const ServiceDescriptor & svc,
                            uint16_t & updateCount)
{
    char serviceName[kMaxDottedNameSize];
    ReturnErrorOnFailure(MakeName(serviceName, sizeof(serviceName), svc.serviceType, zone));

    ReturnErrorOnFailure(writer.PutDeleteRRset(instanceName, RecordType::kSrv));
    ReturnErrorOnFailure(writer.PutDeleteRRset(instanceName, RecordType::kTxt));
    updateCount = static_cast<uint16_t>(updateCount + 2);
    // Remove the PTR mapping for this instance (delete a specific RR).
    ReturnErrorOnFailure(writer.StartRecord(serviceName, RecordType::kPtr, RecordClass::kNone, 0));
    ReturnErrorOnFailure(writer.PutName(instanceName));
    ReturnErrorOnFailure(writer.FinishRecord());
    updateCount = static_cast<uint16_t>(updateCount + 1);
    return CHIP_NO_ERROR;
}

// Encode a single service as add forms (PTR + SRV + TXT). Returns the number of
// update records written.
CHIP_ERROR PutServiceAdd(DnsWriter & writer, const char * zone, const char * hostName, const char * instanceName,
                         const ServiceDescriptor & svc, uint32_t lease, uint16_t & updateCount)
{
    char serviceName[kMaxDottedNameSize];
    ReturnErrorOnFailure(MakeName(serviceName, sizeof(serviceName), svc.serviceType, zone));

    ReturnErrorOnFailure(writer.PutPtr(serviceName, RecordClass::kIn, lease, instanceName));
    ReturnErrorOnFailure(writer.PutSrv(instanceName, RecordClass::kIn, lease, 0, 0, svc.port, hostName));
    ReturnErrorOnFailure(writer.PutTxt(instanceName, RecordClass::kIn, lease, svc.textEntries, svc.textEntryCount));
    updateCount = static_cast<uint16_t>(updateCount + 3);
    return CHIP_NO_ERROR;
}

CHIP_ERROR BuildUpdate(MutableByteSpan & outMessage, const UpdateParams & params, const SrpKeyPair & keyPair, bool removeHost)
{
    VerifyOrReturnError(params.hostLabel != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    const char * zone = ZoneOf(params);
    DnsWriter writer(outMessage.data(), outMessage.size());

    // Header placeholder; counts patched at the end.
    ReturnErrorOnFailure(writer.PutHeader(params.transactionId, MakeFlags(kOpcodeUpdate), 1, 0, 0, 0));

    // Zone section: <zone> SOA IN.
    ReturnErrorOnFailure(writer.PutQuestion(zone, RecordType::kSoa, RecordClass::kIn));

    char hostName[kMaxDottedNameSize];
    ReturnErrorOnFailure(MakeName(hostName, sizeof(hostName), params.hostLabel, zone));

    uint16_t updateCount = 0;

    if (removeHost)
    {
        // Delete each service instance's records and the host AAAA (the AAAA
        // delete signals removal of the whole host and all of its services).
        for (const ServiceDescriptor & svc : params.services)
        {
            char instanceName[kMaxDottedNameSize];
            ReturnErrorOnFailure(MakeName(instanceName, sizeof(instanceName), svc.instanceLabel, svc.serviceType, zone));
            ReturnErrorOnFailure(PutServiceDelete(writer, zone, instanceName, svc, updateCount));
        }
        ReturnErrorOnFailure(writer.PutDeleteRRset(hostName, RecordType::kAaaa));
        updateCount = static_cast<uint16_t>(updateCount + 1);
    }
    else
    {
        // Host AAAA + KEY (refreshes the host and asserts key ownership).
        for (const Inet::IPAddress & address : params.addresses)
        {
            ReturnErrorOnFailure(writer.PutAaaa(hostName, RecordClass::kIn, kHostRecordTtl, address));
            updateCount = static_cast<uint16_t>(updateCount + 1);
        }
        ReturnErrorOnFailure(writer.PutKey(hostName, RecordClass::kIn, params.keyLease, keyPair.GetRawPublicKey()));
        updateCount = static_cast<uint16_t>(updateCount + 1);

        // Per-service: add or delete forms, so one signed UPDATE can register
        // some services and remove others.
        for (const ServiceDescriptor & svc : params.services)
        {
            char instanceName[kMaxDottedNameSize];
            ReturnErrorOnFailure(MakeName(instanceName, sizeof(instanceName), svc.instanceLabel, svc.serviceType, zone));
            if (svc.remove)
            {
                ReturnErrorOnFailure(PutServiceDelete(writer, zone, instanceName, svc, updateCount));
            }
            else
            {
                ReturnErrorOnFailure(PutServiceAdd(writer, zone, hostName, instanceName, svc, params.lease, updateCount));
            }
        }
    }

    // Additional: EDNS Update Lease option + SIG(0). ARCOUNT counts both.
    ReturnErrorOnFailure(PutUpdateLeaseOption(writer, removeHost ? 0 : params.lease, removeHost ? 0 : params.keyLease));
    writer.PatchHeaderCounts(1, 0, updateCount, 2);

    // RFC 2931 SIG(0) validity window. When no wall clock is available the
    // caller leaves both at 0 and we fall back to inception 0 / expiration ==
    // keyLease (accepted by servers that do not enforce the window).
    uint32_t inception  = params.sig0Inception;
    uint32_t expiration = (params.sig0Expiration != 0) ? params.sig0Expiration : params.keyLease;
    ReturnErrorOnFailure(AppendSig0(writer, keyPair, inception, expiration));

    VerifyOrReturnError(writer.Ok(), CHIP_ERROR_BUFFER_TOO_SMALL);
    outMessage.reduce_size(writer.Length());
    return CHIP_NO_ERROR;
}

} // namespace

namespace {

// Derive the service type ("_matter._tcp.zone") from an instance name by
// stripping the leading instance label.
void DeriveServiceType(const char * instanceName, char * out, size_t outSize)
{
    const char * dot = strchr(instanceName, '.');
    if (dot == nullptr)
    {
        out[0] = '\0';
        return;
    }
    snprintf(out, outSize, "%s", dot + 1);
}

ParsedService * FindOrCreateService(ParsedUpdate & out, const char * instanceName)
{
    for (size_t i = 0; i < out.serviceCount; i++)
    {
        if (strcmp(out.services[i].instanceName, instanceName) == 0)
        {
            return &out.services[i];
        }
    }
    if (out.serviceCount >= kMaxParsedServices)
    {
        return nullptr;
    }
    ParsedService & svc = out.services[out.serviceCount++];
    svc                 = {};
    snprintf(svc.instanceName, sizeof(svc.instanceName), "%s", instanceName);
    DeriveServiceType(instanceName, svc.serviceType, sizeof(svc.serviceType));
    return &svc;
}

CHIP_ERROR ParseUpdateLeaseOption(DnsReader & reader, const DnsReader::RecordHeader & rr, ParsedUpdate & out)
{
    // RDATA is a sequence of {option-code(2), option-length(2), option-data}.
    size_t end = rr.rdataOffset + rr.rdlength;
    while (reader.Offset() + 4 <= end)
    {
        uint16_t code, length;
        ReturnErrorOnFailure(reader.ReadU16(code));
        ReturnErrorOnFailure(reader.ReadU16(length));
        if (code == kEdnsOptionUpdateLease && length >= 4)
        {
            ReturnErrorOnFailure(reader.ReadU32(out.lease));
            if (length >= 8)
            {
                ReturnErrorOnFailure(reader.ReadU32(out.keyLease));
            }
            // Skip any remainder of this option.
            size_t consumed = (length >= 8) ? 8u : 4u;
            reader.Seek(reader.Offset() + (length - consumed));
        }
        else
        {
            reader.Seek(reader.Offset() + length);
        }
    }
    return CHIP_NO_ERROR;
}

} // namespace

CHIP_ERROR ParseUpdate(const uint8_t * message, size_t length, ParsedUpdate & out)
{
    out = {};

    DnsReader reader(message, length);
    Header header;
    ReturnErrorOnFailure(reader.ReadHeader(header));
    VerifyOrReturnError(header.Opcode() == kOpcodeUpdate, CHIP_ERROR_INVALID_MESSAGE_TYPE);

    for (uint16_t i = 0; i < header.qdcount; i++)
    {
        ReturnErrorOnFailure(reader.SkipQuestion());
    }
    for (uint16_t i = 0; i < header.ancount; i++)
    {
        DnsReader::RecordHeader rr;
        ReturnErrorOnFailure(reader.ReadRecordHeader(rr));
        ReturnErrorOnFailure(reader.SkipRecordData(rr));
    }

    // Update section.
    for (uint16_t i = 0; i < header.nscount; i++)
    {
        DnsReader::RecordHeader rr;
        ReturnErrorOnFailure(reader.ReadRecordHeader(rr));
        bool isDelete = (rr.klass == RecordClass::kAny || rr.klass == RecordClass::kNone);

        switch (rr.type)
        {
        case RecordType::kAaaa:
            snprintf(out.hostName, sizeof(out.hostName), "%s", rr.name);
            out.hasHost = true;
            if (isDelete)
            {
                out.hostRemoval = true;
            }
            else if (out.addressCount < kMaxParsedAddresses)
            {
                Inet::IPAddress addr;
                ReturnErrorOnFailure(reader.ReadAaaa(addr));
                out.addresses[out.addressCount++] = addr;
            }
            break;
        case RecordType::kKey:
            if (!isDelete)
            {
                size_t keyLen = 0;
                ReturnErrorOnFailure(reader.ReadKey(rr.rdlength, out.publicKey, sizeof(out.publicKey), keyLen));
                out.hasKey = (keyLen == kSrpPublicKeyRawSize);
            }
            break;
        case RecordType::kSrv: {
            ParsedService * svc = FindOrCreateService(out, rr.name);
            VerifyOrReturnError(svc != nullptr, CHIP_ERROR_NO_MEMORY);
            if (isDelete)
            {
                svc->isDelete = true;
            }
            else
            {
                uint16_t priority, weight, port;
                ReturnErrorOnFailure(reader.ReadSrv(priority, weight, port, svc->targetHost, sizeof(svc->targetHost)));
                svc->port = port;
            }
            break;
        }
        case RecordType::kTxt: {
            if (!isDelete)
            {
                ParsedService * svc = FindOrCreateService(out, rr.name);
                VerifyOrReturnError(svc != nullptr, CHIP_ERROR_NO_MEMORY);
                uint16_t copyLen = static_cast<uint16_t>(std::min<size_t>(rr.rdlength, sizeof(svc->txt)));
                memcpy(svc->txt, message + rr.rdataOffset, copyLen);
                svc->txtLen = copyLen;
            }
            break;
        }
        default:
            break;
        }

        ReturnErrorOnFailure(reader.SkipRecordData(rr));
    }

    // Additional section: capture the Update Lease option; skip everything else.
    for (uint16_t i = 0; i < header.arcount; i++)
    {
        DnsReader::RecordHeader rr;
        ReturnErrorOnFailure(reader.ReadRecordHeader(rr));
        if (rr.type == RecordType::kOpt)
        {
            ReturnErrorOnFailure(ParseUpdateLeaseOption(reader, rr, out));
        }
        ReturnErrorOnFailure(reader.SkipRecordData(rr));
    }

    if (out.lease == 0 && !out.hostRemoval)
    {
        // No explicit lease option and no host delete: treat as a default lease.
        // A zero lease is only a host removal when paired with a host record.
        if (out.hasHost && out.addressCount == 0)
        {
            out.hostRemoval = true;
        }
        else
        {
            out.lease = 7200;
        }
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR ParseUpdateResponse(const uint8_t * message, size_t length, UpdateResponse & out)
{
    out = {};

    DnsReader reader(message, length);
    Header header;
    ReturnErrorOnFailure(reader.ReadHeader(header));
    VerifyOrReturnError(header.IsResponse(), CHIP_ERROR_INVALID_MESSAGE_TYPE);

    out.transactionId = header.id;
    out.rcode         = header.Rcode();

    // Skip zone/question, prerequisite and update sections; the granted lease
    // (if any) is echoed in the additional section's OPT record.
    for (uint16_t i = 0; i < header.qdcount; i++)
    {
        ReturnErrorOnFailure(reader.SkipQuestion());
    }
    uint32_t nonAr = static_cast<uint32_t>(header.ancount) + header.nscount;
    for (uint32_t i = 0; i < nonAr; i++)
    {
        DnsReader::RecordHeader rr;
        ReturnErrorOnFailure(reader.ReadRecordHeader(rr));
        ReturnErrorOnFailure(reader.SkipRecordData(rr));
    }
    for (uint16_t i = 0; i < header.arcount; i++)
    {
        DnsReader::RecordHeader rr;
        ReturnErrorOnFailure(reader.ReadRecordHeader(rr));
        if (rr.type == RecordType::kOpt)
        {
            ParsedUpdate scratch = {};
            ReturnErrorOnFailure(ParseUpdateLeaseOption(reader, rr, scratch));
            if (scratch.lease != 0 || scratch.keyLease != 0)
            {
                out.hasLease = true;
                out.lease    = scratch.lease;
                out.keyLease = scratch.keyLease;
            }
        }
        ReturnErrorOnFailure(reader.SkipRecordData(rr));
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR BuildRegisterUpdate(MutableByteSpan & outMessage, const UpdateParams & params, const SrpKeyPair & keyPair)
{
    return BuildUpdate(outMessage, params, keyPair, /*removeHost=*/false);
}

CHIP_ERROR BuildRemoveUpdate(MutableByteSpan & outMessage, const UpdateParams & params, const SrpKeyPair & keyPair)
{
    return BuildUpdate(outMessage, params, keyPair, /*removeHost=*/true);
}

} // namespace Srp
} // namespace Dnssd
} // namespace chip
