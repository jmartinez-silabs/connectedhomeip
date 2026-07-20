/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *    All rights reserved.
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

#include <lib/dnssd/SrpDnsMessage.h>
#include <lib/dnssd/SrpKeyPair.h>
#include <lib/dnssd/SrpUpdate.h>

#include <cstring>

#include <pw_unit_test/framework.h>

#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/CHIPMem.h>

using namespace chip;
using namespace chip::Dnssd::Srp;

namespace {

TEST(TestSrpDnsMessage, HeaderRoundTrip)
{
    uint8_t buffer[64];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutHeader(0x1234, MakeFlags(kOpcodeUpdate), 1, 0, 2, 1), CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    Header header;
    ASSERT_EQ(reader.ReadHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.id, 0x1234);
    EXPECT_EQ(header.Opcode(), kOpcodeUpdate);
    EXPECT_FALSE(header.IsResponse());
    EXPECT_EQ(header.qdcount, 1);
    EXPECT_EQ(header.nscount, 2);
    EXPECT_EQ(header.arcount, 1);
}

TEST(TestSrpDnsMessage, NameRoundTrip)
{
    uint8_t buffer[128];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutQuestion("myhost._matter._tcp.default.service.arpa", RecordType::kSrv, RecordClass::kIn),
              CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    char name[kMaxDottedNameSize];
    ASSERT_EQ(reader.ReadName(name, sizeof(name)), CHIP_NO_ERROR);
    EXPECT_STREQ(name, "myhost._matter._tcp.default.service.arpa");
    uint16_t type, klass;
    ASSERT_EQ(reader.ReadU16(type), CHIP_NO_ERROR);
    ASSERT_EQ(reader.ReadU16(klass), CHIP_NO_ERROR);
    EXPECT_EQ(type, static_cast<uint16_t>(RecordType::kSrv));
    EXPECT_EQ(klass, static_cast<uint16_t>(RecordClass::kIn));
}

TEST(TestSrpDnsMessage, RootNameRoundTrip)
{
    uint8_t buffer[16];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutName(""), CHIP_NO_ERROR);
    EXPECT_EQ(writer.Length(), 1u); // single root octet

    DnsReader reader(buffer, writer.Length());
    char name[kMaxDottedNameSize];
    ASSERT_EQ(reader.ReadName(name, sizeof(name)), CHIP_NO_ERROR);
    EXPECT_STREQ(name, "");
}

TEST(TestSrpDnsMessage, SrvRoundTrip)
{
    uint8_t buffer[256];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutSrv("inst._matter._tcp.default.service.arpa", RecordClass::kIn, 3600, 1, 2, 5540,
                            "myhost.default.service.arpa"),
              CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    DnsReader::RecordHeader header;
    ASSERT_EQ(reader.ReadRecordHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.type, RecordType::kSrv);
    EXPECT_EQ(header.ttl, 3600u);

    uint16_t priority, weight, port;
    char target[kMaxDottedNameSize];
    ASSERT_EQ(reader.ReadSrv(priority, weight, port, target, sizeof(target)), CHIP_NO_ERROR);
    EXPECT_EQ(priority, 1);
    EXPECT_EQ(weight, 2);
    EXPECT_EQ(port, 5540);
    EXPECT_STREQ(target, "myhost.default.service.arpa");
}

TEST(TestSrpDnsMessage, TxtRoundTrip)
{
    const uint8_t val1[] = { 'A', 'B' };
    Dnssd::TextEntry entries[2];
    entries[0].mKey      = "CM";
    entries[0].mData     = val1;
    entries[0].mDataSize = sizeof(val1);
    entries[1].mKey      = "T";
    entries[1].mData     = nullptr;
    entries[1].mDataSize = 0;

    uint8_t buffer[256];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutTxt("inst._matter._tcp.default.service.arpa", RecordClass::kIn, 3600, entries, 2), CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    DnsReader::RecordHeader header;
    ASSERT_EQ(reader.ReadRecordHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.type, RecordType::kTxt);

    // RDATA: "CM=AB" (len 5), "T" (len 1)
    const uint8_t * rdata = reader.Data() + header.rdataOffset;
    ASSERT_EQ(rdata[0], 5);
    EXPECT_EQ(memcmp(rdata + 1, "CM=AB", 5), 0);
    EXPECT_EQ(rdata[6], 1);
    EXPECT_EQ(rdata[7], 'T');
}

TEST(TestSrpDnsMessage, AaaaRoundTrip)
{
    Inet::IPAddress address;
    ASSERT_TRUE(Inet::IPAddress::FromString("fe80::1234:5678", address));

    uint8_t buffer[128];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutAaaa("myhost.default.service.arpa", RecordClass::kIn, 120, address), CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    DnsReader::RecordHeader header;
    ASSERT_EQ(reader.ReadRecordHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.type, RecordType::kAaaa);
    EXPECT_EQ(header.rdlength, 16);

    Inet::IPAddress decoded;
    ASSERT_EQ(reader.ReadAaaa(decoded), CHIP_NO_ERROR);
    EXPECT_EQ(decoded, address);
}

TEST(TestSrpDnsMessage, PtrRoundTrip)
{
    uint8_t buffer[128];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutPtr("_matter._tcp.default.service.arpa", RecordClass::kIn, 3600,
                            "inst._matter._tcp.default.service.arpa"),
              CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    DnsReader::RecordHeader header;
    ASSERT_EQ(reader.ReadRecordHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.type, RecordType::kPtr);

    char target[kMaxDottedNameSize];
    ASSERT_EQ(reader.ReadPtr(target, sizeof(target)), CHIP_NO_ERROR);
    EXPECT_STREQ(target, "inst._matter._tcp.default.service.arpa");
}

TEST(TestSrpDnsMessage, DeleteRRsetForm)
{
    uint8_t buffer[128];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutDeleteRRset("inst._matter._tcp.default.service.arpa", RecordType::kSrv), CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    DnsReader::RecordHeader header;
    ASSERT_EQ(reader.ReadRecordHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.type, RecordType::kSrv);
    EXPECT_EQ(header.klass, RecordClass::kAny);
    EXPECT_EQ(header.ttl, 0u);
    EXPECT_EQ(header.rdlength, 0);
}

TEST(TestSrpDnsMessage, CompressedNameDecode)
{
    // Manually craft: "a.bc" at offset 12, then a pointer to it at a later offset.
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));
    size_t o          = 12;
    buffer[o++]       = 1;
    buffer[o++]       = 'a';
    buffer[o++]       = 2;
    buffer[o++]       = 'b';
    buffer[o++]       = 'c';
    buffer[o++]       = 0;
    size_t pointerPos = o;
    buffer[o++]       = 0xC0; // pointer high bits
    buffer[o++]       = 12;   // -> offset 12

    DnsReader reader(buffer, o);
    reader.Seek(pointerPos);
    char name[kMaxDottedNameSize];
    ASSERT_EQ(reader.ReadName(name, sizeof(name)), CHIP_NO_ERROR);
    EXPECT_STREQ(name, "a.bc");
    // The reader must have advanced by exactly the 2 pointer bytes.
    EXPECT_EQ(reader.Offset(), pointerPos + 2);
}

TEST(TestSrpDnsMessage, WriterReportsBufferTooSmall)
{
    uint8_t buffer[4];
    DnsWriter writer(buffer, sizeof(buffer));
    EXPECT_NE(writer.PutHeader(1, 0, 0, 0, 0, 0), CHIP_NO_ERROR);
    EXPECT_FALSE(writer.Ok());
}

TEST(TestSrpDnsMessage, KeyRecordRoundTrip)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);
    ByteSpan pubKey = keyPair.GetRawPublicKey();
    EXPECT_EQ(pubKey.size(), kSrpPublicKeyRawSize);

    uint8_t buffer[256];
    DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutKey("myhost.default.service.arpa", RecordClass::kIn, 3600, pubKey), CHIP_NO_ERROR);

    DnsReader reader(buffer, writer.Length());
    DnsReader::RecordHeader header;
    ASSERT_EQ(reader.ReadRecordHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.type, RecordType::kKey);

    uint8_t decoded[kSrpPublicKeyRawSize];
    size_t decodedLen = 0;
    ASSERT_EQ(reader.ReadKey(header.rdlength, decoded, sizeof(decoded), decodedLen), CHIP_NO_ERROR);
    EXPECT_EQ(decodedLen, kSrpPublicKeyRawSize);
    EXPECT_EQ(memcmp(decoded, pubKey.data(), kSrpPublicKeyRawSize), 0);
}

TEST(TestSrpDnsMessage, SignAndVerify)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    const uint8_t message[] = "srp update payload bytes";
    uint8_t signatureBuf[kSrpSignatureRawSize];
    MutableByteSpan signature(signatureBuf);
    ASSERT_EQ(keyPair.Sign(ByteSpan(message, sizeof(message)), signature), CHIP_NO_ERROR);
    EXPECT_EQ(signature.size(), kSrpSignatureRawSize);

    EXPECT_EQ(SrpKeyPair::Verify(keyPair.GetRawPublicKey(), ByteSpan(message, sizeof(message)), signature), CHIP_NO_ERROR);

    // Tampered message must fail verification.
    const uint8_t tampered[] = "srp update payload bytez";
    EXPECT_NE(SrpKeyPair::Verify(keyPair.GetRawPublicKey(), ByteSpan(tampered, sizeof(tampered)), signature), CHIP_NO_ERROR);
}

TEST(TestSrpDnsMessage, KeyTagIsDeterministic)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);
    EXPECT_EQ(keyPair.ComputeKeyTag(), SrpKeyPair::ComputeKeyTag(keyPair.GetRawPublicKey()));
}

TEST(TestSrpDnsMessage, BuildAndVerifyRegisterUpdate)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    Inet::IPAddress address;
    ASSERT_TRUE(Inet::IPAddress::FromString("fe80::1", address));

    const uint8_t dValue[] = { '5', '5', '4', '0' };
    Dnssd::TextEntry txt;
    txt.mKey      = "SII";
    txt.mData     = dValue;
    txt.mDataSize = sizeof(dValue);

    ServiceDescriptor service;
    service.instanceLabel  = "B75AFB458ECD";
    service.serviceType    = "_matter._tcp";
    service.port           = 5540;
    service.textEntries    = &txt;
    service.textEntryCount = 1;

    UpdateParams params;
    params.transactionId = 0x4242;
    params.zone          = nullptr; // default zone
    params.hostLabel     = "B75AFB458ECD0000";
    params.addresses     = Span<const Inet::IPAddress>(&address, 1);
    params.services      = Span<const ServiceDescriptor>(&service, 1);
    params.lease         = 3600;
    params.keyLease      = 7200;

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(BuildRegisterUpdate(message, params, keyPair), CHIP_NO_ERROR);
    EXPECT_GT(message.size(), kDnsHeaderSize);

    // The trailing SIG(0) verifies against the signing key.
    EXPECT_EQ(VerifySig0(message.data(), message.size(), keyPair.GetRawPublicKey()), CHIP_NO_ERROR);

    // A different key must not verify.
    SrpKeyPair otherKey;
    ASSERT_EQ(otherKey.InitEphemeral(), CHIP_NO_ERROR);
    EXPECT_NE(VerifySig0(message.data(), message.size(), otherKey.GetRawPublicKey()), CHIP_NO_ERROR);

    // Header should be an UPDATE with one zone entry.
    DnsReader reader(message.data(), message.size());
    Header header;
    ASSERT_EQ(reader.ReadHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.Opcode(), kOpcodeUpdate);
    EXPECT_EQ(header.qdcount, 1);
    EXPECT_GT(header.nscount, 0);
    EXPECT_EQ(header.arcount, 2); // OPT + SIG(0)
}

TEST(TestSrpDnsMessage, TamperedUpdateFailsVerification)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    Inet::IPAddress address;
    ASSERT_TRUE(Inet::IPAddress::FromString("fe80::2", address));

    ServiceDescriptor service;
    service.instanceLabel  = "ABCDEF012345";
    service.serviceType    = "_matterc._udp";
    service.port           = 5540;
    service.textEntries    = nullptr;
    service.textEntryCount = 0;

    UpdateParams params;
    params.transactionId = 1;
    params.zone          = nullptr;
    params.hostLabel     = "ABCDEF0123450000";
    params.addresses     = Span<const Inet::IPAddress>(&address, 1);
    params.services      = Span<const ServiceDescriptor>(&service, 1);
    params.lease         = 3600;
    params.keyLease      = 7200;

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(BuildRegisterUpdate(message, params, keyPair), CHIP_NO_ERROR);

    // Flip a byte inside the update body (the port in the SRV record region).
    buffer[kDnsHeaderSize + 4] ^= 0xFF;
    EXPECT_NE(VerifySig0(message.data(), message.size(), keyPair.GetRawPublicKey()), CHIP_NO_ERROR);
}

} // namespace
