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

#include <lib/dnssd/InfraDnssd.h>
#include <lib/dnssd/InfraDnssdServer.h>
#include <lib/dnssd/InfraDnssdServerImpl.h>
#include <lib/dnssd/SrpKeyPair.h>
#include <lib/dnssd/SrpUpdate.h>

#include <pw_unit_test/framework.h>

#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/CHIPMem.h>
#include <system/RAIIMockClock.h>

using namespace chip;
using namespace chip::Dnssd;

namespace {

Inet::IPAddress AddressFor(const char * text)
{
    Inet::IPAddress address;
    VerifyOrDie(Inet::IPAddress::FromString(text, address));
    return address;
}

class CountingProviderDelegate : public InfraProviderDelegate
{
public:
    void OnInfraProviderAvailable(const InfraProvider & provider) override
    {
        mAvailableCount++;
        mLastProvider = provider;
    }

    void OnInfraProviderLost() override { mLostCount++; }

    int mAvailableCount           = 0;
    int mLostCount                = 0;
    InfraProvider mLastProvider   = {};
};

// A minimal InfraDnssdServer implementation used only to exercise the settable
// singleton accessor.
class NoopInfraDnssdServer : public InfraDnssdServer
{
public:
    CHIP_ERROR Init(InfraDnssdServerDelegate *) override { return CHIP_NO_ERROR; }
    void Shutdown() override {}
    CHIP_ERROR Start(uint16_t) override { return CHIP_NO_ERROR; }
    CHIP_ERROR Stop() override { return CHIP_NO_ERROR; }
    CHIP_ERROR SetAdvertiseInfraFlag(bool) override { return CHIP_NO_ERROR; }
    bool IsRunning() const override { return false; }
    uint16_t GetRegisteredServiceCount() const override { return 0; }
};

TEST(TestInfraDnssd, InitRequiresDelegate)
{
    InfraDnssdManager manager;
    EXPECT_EQ(manager.Init(nullptr), CHIP_ERROR_INVALID_ARGUMENT);
}

TEST(TestInfraDnssd, DoubleInitFails)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;

    EXPECT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);
    EXPECT_EQ(manager.Init(&delegate), CHIP_ERROR_INCORRECT_STATE);
    manager.Shutdown();
}

TEST(TestInfraDnssd, NoProviderInitially)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    EXPECT_FALSE(manager.HasProvider());
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kNone);
    manager.Shutdown();
}

TEST(TestInfraDnssd, EventsIgnoredBeforeInit)
{
    InfraDnssdManager manager;
    // No Init(): every event is a no-op and no provider is selected.
    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), 1800, /*hasInfraFlag=*/true, /*hasSnacFlag=*/false);
    manager.OnAdHocProviderDiscovered(AddressFor("fe80::2"), 5353);
    EXPECT_FALSE(manager.HasProvider());
}

TEST(TestInfraDnssd, InfraRouterDiscoveredViaRa)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), /*routerLifetime=*/1800, /*hasInfraFlag=*/true,
                                          /*hasSnacFlag=*/false);

    EXPECT_TRUE(manager.HasProvider());
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kInfraRouter);
    EXPECT_EQ(delegate.mAvailableCount, 1);
    EXPECT_EQ(delegate.mLastProvider.type, InfraProviderType::kInfraRouter);
    manager.Shutdown();
}

TEST(TestInfraDnssd, InfraFlagWithoutLifetimeIgnored)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    // Infra flag set but router lifetime is 0 -> not an infrastructure router.
    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), /*routerLifetime=*/0, /*hasInfraFlag=*/true,
                                          /*hasSnacFlag=*/false);

    EXPECT_FALSE(manager.HasProvider());
    EXPECT_EQ(delegate.mAvailableCount, 0);
    manager.Shutdown();
}

TEST(TestInfraDnssd, SnacRouterDiscoveredViaRa)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), /*routerLifetime=*/0, /*hasInfraFlag=*/false,
                                          /*hasSnacFlag=*/true);

    EXPECT_TRUE(manager.HasProvider());
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kSnacRouter);
    manager.Shutdown();
}

TEST(TestInfraDnssd, RaWithoutFlagsIgnored)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), /*routerLifetime=*/1800, /*hasInfraFlag=*/false,
                                          /*hasSnacFlag=*/false);

    EXPECT_FALSE(manager.HasProvider());
    manager.Shutdown();
}

TEST(TestInfraDnssd, AdHocProviderDiscovered)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    manager.OnAdHocProviderDiscovered(AddressFor("fe80::2"), 5353);

    EXPECT_TRUE(manager.HasProvider());
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kAdHocProvider);
    EXPECT_EQ(manager.GetCurrentProvider().port, 5353);
    manager.Shutdown();
}

TEST(TestInfraDnssd, HigherPriorityProviderReplacesLower)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    // Start with the lowest priority provider (ad-hoc).
    manager.OnAdHocProviderDiscovered(AddressFor("fe80::2"), 5353);
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kAdHocProvider);

    // A SNAC router outranks ad-hoc.
    manager.OnRouterAdvertisementReceived(AddressFor("fe80::3"), 0, false, true);
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kSnacRouter);

    // A CE (infrastructure) router outranks SNAC.
    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), 1800, true, false);
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kInfraRouter);

    manager.Shutdown();
}

TEST(TestInfraDnssd, LowerPriorityProviderDoesNotReplaceHigher)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), 1800, true, false);
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kInfraRouter);
    int availableAfterInfra = delegate.mAvailableCount;

    // Ad-hoc is lower priority and must be ignored while a CE router is present.
    manager.OnAdHocProviderDiscovered(AddressFor("fe80::2"), 5353);
    EXPECT_EQ(manager.GetCurrentProvider().type, InfraProviderType::kInfraRouter);
    EXPECT_EQ(delegate.mAvailableCount, availableAfterInfra);

    manager.Shutdown();
}

TEST(TestInfraDnssd, ProviderUnreachableResetsAndNotifies)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    manager.OnRouterAdvertisementReceived(AddressFor("fe80::1"), 1800, true, false);
    ASSERT_TRUE(manager.HasProvider());

    manager.OnProviderUnreachable();

    EXPECT_FALSE(manager.HasProvider());
    EXPECT_EQ(delegate.mLostCount, 1);
    manager.Shutdown();
}

TEST(TestInfraDnssd, RegisterServiceWithoutProviderFails)
{
    InfraDnssdManager manager;
    CountingProviderDelegate delegate;
    ASSERT_EQ(manager.Init(&delegate), CHIP_NO_ERROR);

    DnssdService service = {};
    EXPECT_EQ(manager.RegisterService(service), CHIP_ERROR_NOT_CONNECTED);
    manager.Shutdown();
}

TEST(TestInfraDnssd, ServerSingletonSetAndGet)
{
    NoopInfraDnssdServer server;
    InfraDnssdServer::SetInstance(server);
    EXPECT_EQ(&InfraDnssdServer::Instance(), &server);
}

// ---------------------------------------------------------------------------
// SRP server (InfraDnssdServerImpl) end-to-end message handling.
// ---------------------------------------------------------------------------

class CountingServerDelegate : public InfraDnssdServerDelegate
{
public:
    void OnServiceRegistered(const Inet::IPAddress &, const char * hostName, const char * instanceName, const char *,
                             uint16_t) override
    {
        mRegistered++;
    }
    void OnServiceRemoved(const char *, const char *) override { mRemoved++; }

    int mRegistered = 0;
    int mRemoved    = 0;
};

CHIP_ERROR BuildTestUpdate(const Srp::SrpKeyPair & keyPair, const char * hostLabel, bool remove, MutableByteSpan & out)
{
    Inet::IPAddress address;
    VerifyOrReturnError(Inet::IPAddress::FromString("fe80::abcd", address), CHIP_ERROR_INTERNAL);

    Srp::ServiceDescriptor service;
    service.instanceLabel  = "B75AFB458ECD";
    service.serviceType    = "_matter._tcp";
    service.port           = 5540;
    service.textEntries    = nullptr;
    service.textEntryCount = 0;

    Srp::UpdateParams params;
    params.transactionId = 0x1111;
    params.zone          = nullptr;
    params.hostLabel     = hostLabel;
    params.addresses     = Span<const Inet::IPAddress>(&address, 1);
    params.services      = Span<const Srp::ServiceDescriptor>(&service, 1);
    params.lease         = 3600;
    params.keyLease      = 7200;

    return remove ? Srp::BuildRemoveUpdate(out, params, keyPair) : Srp::BuildRegisterUpdate(out, params, keyPair);
}

// Like BuildTestUpdate but lets the caller pick the instance label, host label
// and host address so multiple distinct services can share a service type.
CHIP_ERROR BuildTestUpdateFor(const Srp::SrpKeyPair & keyPair, const char * hostLabel, const char * instanceLabel,
                              const char * addressText, MutableByteSpan & out)
{
    Inet::IPAddress address;
    VerifyOrReturnError(Inet::IPAddress::FromString(addressText, address), CHIP_ERROR_INTERNAL);

    Srp::ServiceDescriptor service;
    service.instanceLabel  = instanceLabel;
    service.serviceType    = "_matter._tcp";
    service.port           = 5540;
    service.textEntries    = nullptr;
    service.textEntryCount = 0;

    Srp::UpdateParams params;
    params.transactionId = 0x1111;
    params.zone          = nullptr;
    params.hostLabel     = hostLabel;
    params.addresses     = Span<const Inet::IPAddress>(&address, 1);
    params.services      = Span<const Srp::ServiceDescriptor>(&service, 1);
    params.lease         = 3600;
    params.keyLease      = 7200;

    return Srp::BuildRegisterUpdate(out, params, keyPair);
}

TEST(TestInfraDnssd, ServerAcceptsSignedRegistration)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0001", false, message), CHIP_NO_ERROR);

    EXPECT_EQ(server.ProcessUpdate(message.data(), message.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);
    EXPECT_EQ(server.GetRegisteredServiceCount(), 1);
    EXPECT_EQ(delegate.mRegistered, 1);
    EXPECT_NE(server.FindHost("HOST0001.default.service.arpa"), nullptr);
}

TEST(TestInfraDnssd, ServerRejectsBadSignature)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0002", false, message), CHIP_NO_ERROR);
    buffer[Srp::kDnsHeaderSize + 6] ^= 0xFF; // corrupt the update body

    EXPECT_EQ(server.ProcessUpdate(message.data(), message.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNotAuth);
    EXPECT_EQ(server.GetRegisteredServiceCount(), 0);
}

TEST(TestInfraDnssd, ServerRemovesServices)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t buffer[1600];
    MutableByteSpan registerMsg(buffer);
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0003", false, registerMsg), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(registerMsg.data(), registerMsg.size(), AddressFor("fe80::abcd")),
              Srp::ResponseCode::kNoError);
    ASSERT_EQ(server.GetRegisteredServiceCount(), 1);

    uint8_t removeBuffer[1600];
    MutableByteSpan removeMsg(removeBuffer);
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0003", true, removeMsg), CHIP_NO_ERROR);
    EXPECT_EQ(server.ProcessUpdate(removeMsg.data(), removeMsg.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);
    EXPECT_EQ(server.GetRegisteredServiceCount(), 0);
    EXPECT_GE(delegate.mRemoved, 1);
}

TEST(TestInfraDnssd, ServerEnforcesFirstComeFirstServed)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyA, keyB;
    ASSERT_EQ(keyA.InitEphemeral(), CHIP_NO_ERROR);
    ASSERT_EQ(keyB.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t bufferA[1600];
    MutableByteSpan messageA(bufferA);
    ASSERT_EQ(BuildTestUpdate(keyA, "HOST0004", false, messageA), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(messageA.data(), messageA.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);

    // A different key claiming the same host name must be rejected.
    uint8_t bufferB[1600];
    MutableByteSpan messageB(bufferB);
    ASSERT_EQ(BuildTestUpdate(keyB, "HOST0004", false, messageB), CHIP_NO_ERROR);
    EXPECT_EQ(server.ProcessUpdate(messageB.data(), messageB.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNotAuth);
}

// Build a signed UPDATE for a single host carrying two services. When @a
// removeB is true the second service is encoded with delete forms, exercising a
// combined add/delete UPDATE.
CHIP_ERROR BuildTwoServiceUpdate(const Srp::SrpKeyPair & keyPair, const char * hostLabel, const char * instanceA,
                                 const char * instanceB, bool removeB, MutableByteSpan & out)
{
    Inet::IPAddress address;
    VerifyOrReturnError(Inet::IPAddress::FromString("fe80::abcd", address), CHIP_ERROR_INTERNAL);

    Srp::ServiceDescriptor services[2] = {};
    services[0].instanceLabel          = instanceA;
    services[0].serviceType            = "_matter._tcp";
    services[0].port                   = 5540;
    services[1].instanceLabel          = instanceB;
    services[1].serviceType            = "_matter._tcp";
    services[1].port                   = 5541;
    services[1].remove                 = removeB;

    Srp::UpdateParams params;
    params.transactionId = 0x3333;
    params.zone          = nullptr;
    params.hostLabel     = hostLabel;
    params.addresses     = Span<const Inet::IPAddress>(&address, 1);
    params.services      = Span<const Srp::ServiceDescriptor>(services, 2);
    params.lease         = 3600;
    params.keyLease      = 7200;

    return Srp::BuildRegisterUpdate(out, params, keyPair);
}

TEST(TestInfraDnssd, ServerCombinedAddAndDelete)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    // Register two services under one host.
    uint8_t buf1[1600];
    MutableByteSpan msg1(buf1);
    ASSERT_EQ(BuildTwoServiceUpdate(keyPair, "HOSTCMB1", "AAAAAAAAAAAA", "BBBBBBBBBBBB", /*removeB=*/false, msg1),
              CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(msg1.data(), msg1.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);
    ASSERT_EQ(server.GetRegisteredServiceCount(), 2);

    // Re-send keeping the first service and deleting the second in one UPDATE.
    uint8_t buf2[1600];
    MutableByteSpan msg2(buf2);
    ASSERT_EQ(BuildTwoServiceUpdate(keyPair, "HOSTCMB1", "AAAAAAAAAAAA", "BBBBBBBBBBBB", /*removeB=*/true, msg2),
              CHIP_NO_ERROR);
    EXPECT_EQ(server.ProcessUpdate(msg2.data(), msg2.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);

    // The host survives (per-service delete is not a host removal) and only the
    // first service remains registered.
    EXPECT_EQ(server.GetRegisteredServiceCount(), 1);
    EXPECT_NE(server.FindHost("HOSTCMB1.default.service.arpa"), nullptr);
}

TEST(TestInfraDnssd, ServerClampsAndGrantsLease)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    Inet::IPAddress address = AddressFor("fe80::abcd");
    Srp::ServiceDescriptor service;
    service.instanceLabel  = "CCCCCCCCCCCC";
    service.serviceType    = "_matter._tcp";
    service.port           = 5540;
    service.textEntries    = nullptr;
    service.textEntryCount = 0;

    // Request a lease far above the server's policy maximum.
    Srp::UpdateParams params;
    params.transactionId = 0x1212;
    params.zone          = nullptr;
    params.hostLabel     = "HOSTLEAS";
    params.addresses     = Span<const Inet::IPAddress>(&address, 1);
    params.services      = Span<const Srp::ServiceDescriptor>(&service, 1);
    params.lease         = 1000000;
    params.keyLease      = 100000000;

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(Srp::BuildRegisterUpdate(message, params, keyPair), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint32_t grantedLease    = 0;
    uint32_t grantedKeyLease = 0;
    EXPECT_EQ(server.ProcessUpdate(message.data(), message.size(), address, &grantedLease, &grantedKeyLease),
              Srp::ResponseCode::kNoError);
    EXPECT_EQ(grantedLease, kMaxGrantedLeaseSeconds);
    EXPECT_EQ(grantedKeyLease, kMaxGrantedKeyLeaseSeconds);
}

TEST(TestInfraDnssd, ParseUpdateResponseWithLease)
{
    uint8_t buffer[64];
    Srp::DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutHeader(0x4444, Srp::MakeFlags(Srp::kOpcodeUpdate, /*response=*/true, Srp::ResponseCode::kNoError), 0, 0,
                               0, 1),
              CHIP_NO_ERROR);
    ASSERT_EQ(Srp::PutUpdateLeaseOption(writer, 3600, 7200), CHIP_NO_ERROR);
    ASSERT_TRUE(writer.Ok());

    Srp::UpdateResponse response;
    ASSERT_EQ(Srp::ParseUpdateResponse(buffer, writer.Length(), response), CHIP_NO_ERROR);
    EXPECT_EQ(response.transactionId, 0x4444);
    EXPECT_EQ(response.rcode, Srp::ResponseCode::kNoError);
    EXPECT_TRUE(response.hasLease);
    EXPECT_EQ(response.lease, 3600u);
    EXPECT_EQ(response.keyLease, 7200u);
}

TEST(TestInfraDnssd, ParseUpdateResponseRejectedNoLease)
{
    uint8_t buffer[16];
    Srp::DnsWriter writer(buffer, sizeof(buffer));
    ASSERT_EQ(writer.PutHeader(0x5555, Srp::MakeFlags(Srp::kOpcodeUpdate, /*response=*/true, Srp::ResponseCode::kRefused), 0, 0,
                               0, 0),
              CHIP_NO_ERROR);

    Srp::UpdateResponse response;
    ASSERT_EQ(Srp::ParseUpdateResponse(buffer, writer.Length(), response), CHIP_NO_ERROR);
    EXPECT_EQ(response.transactionId, 0x5555);
    EXPECT_EQ(response.rcode, Srp::ResponseCode::kRefused);
    EXPECT_FALSE(response.hasLease);
}

// ---------------------------------------------------------------------------
// Discovery Proxy: unicast DNS query answering from the zone table.
// ---------------------------------------------------------------------------

size_t BuildQuery(uint8_t * buffer, size_t bufferSize, const char * name, Srp::RecordType type)
{
    Srp::DnsWriter writer(buffer, bufferSize);
    VerifyOrDie(writer.PutHeader(0x2222, Srp::MakeFlags(Srp::kOpcodeQuery), /*qdcount=*/1, 0, 0, 0) == CHIP_NO_ERROR);
    VerifyOrDie(writer.PutQuestion(name, type, Srp::RecordClass::kIn) == CHIP_NO_ERROR);
    return writer.Length();
}

// Count the answer records of a given type in a DNS response.
uint16_t CountAnswers(const uint8_t * message, size_t length, Srp::RecordType type)
{
    Srp::DnsReader reader(message, length);
    Srp::Header header;
    VerifyOrDie(reader.ReadHeader(header) == CHIP_NO_ERROR);
    for (uint16_t i = 0; i < header.qdcount; i++)
    {
        VerifyOrDie(reader.SkipQuestion() == CHIP_NO_ERROR);
    }
    uint16_t matches = 0;
    for (uint16_t i = 0; i < header.ancount; i++)
    {
        Srp::DnsReader::RecordHeader rr;
        VerifyOrDie(reader.ReadRecordHeader(rr) == CHIP_NO_ERROR);
        if (rr.type == type)
        {
            matches++;
        }
        VerifyOrDie(reader.SkipRecordData(rr) == CHIP_NO_ERROR);
    }
    return matches;
}

TEST(TestInfraDnssd, DiscoveryProxyAnswersPtrBrowse)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0005", false, message), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(message.data(), message.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);

    uint8_t query[256];
    size_t queryLen = BuildQuery(query, sizeof(query), "_matter._tcp.default.service.arpa", Srp::RecordType::kPtr);

    uint8_t response[512];
    size_t responseLen = 0;
    EXPECT_EQ(server.BuildQueryResponse(query, queryLen, response, sizeof(response), responseLen), Srp::ResponseCode::kNoError);
    ASSERT_GT(responseLen, 0u);
    EXPECT_EQ(CountAnswers(response, responseLen, Srp::RecordType::kPtr), 1);
}

TEST(TestInfraDnssd, DiscoveryProxyAnswersPtrBrowseWithMultipleServices)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyA, keyB;
    ASSERT_EQ(keyA.InitEphemeral(), CHIP_NO_ERROR);
    ASSERT_EQ(keyB.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    // Two distinct instances of the same service type, each with its own host.
    uint8_t bufferA[1600];
    MutableByteSpan messageA(bufferA);
    ASSERT_EQ(BuildTestUpdateFor(keyA, "HOSTMS01", "AAAAAAAAAAAA", "fe80::a", messageA), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(messageA.data(), messageA.size(), AddressFor("fe80::a")), Srp::ResponseCode::kNoError);

    uint8_t bufferB[1600];
    MutableByteSpan messageB(bufferB);
    ASSERT_EQ(BuildTestUpdateFor(keyB, "HOSTMS02", "BBBBBBBBBBBB", "fe80::b", messageB), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(messageB.data(), messageB.size(), AddressFor("fe80::b")), Srp::ResponseCode::kNoError);
    ASSERT_EQ(server.GetRegisteredServiceCount(), 2);

    uint8_t query[256];
    size_t queryLen = BuildQuery(query, sizeof(query), "_matter._tcp.default.service.arpa", Srp::RecordType::kPtr);

    // Large enough to hold two full service records (PTR + SRV + TXT + AAAA);
    // the writer does not use DNS name compression.
    uint8_t response[1024];
    size_t responseLen = 0;
    EXPECT_EQ(server.BuildQueryResponse(query, queryLen, response, sizeof(response), responseLen), Srp::ResponseCode::kNoError);
    ASSERT_GT(responseLen, 0u);

    // Both PTR records must appear within the answer section (the first ancount
    // records). CountAnswers reads exactly ancount records, matching how a
    // browse client parses the answer section: it returns 2 only if the answer
    // section is not polluted by additional-section SRV/TXT/AAAA records.
    Srp::DnsReader header_reader(response, responseLen);
    Srp::Header header;
    ASSERT_EQ(header_reader.ReadHeader(header), CHIP_NO_ERROR);
    EXPECT_EQ(header.ancount, 2);
    EXPECT_EQ(CountAnswers(response, responseLen, Srp::RecordType::kPtr), 2);
}

TEST(TestInfraDnssd, DiscoveryProxyAnswersSrvResolve)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0006", false, message), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(message.data(), message.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);

    uint8_t query[256];
    size_t queryLen =
        BuildQuery(query, sizeof(query), "B75AFB458ECD._matter._tcp.default.service.arpa", Srp::RecordType::kSrv);

    uint8_t response[512];
    size_t responseLen = 0;
    EXPECT_EQ(server.BuildQueryResponse(query, queryLen, response, sizeof(response), responseLen), Srp::ResponseCode::kNoError);
    ASSERT_GT(responseLen, 0u);
    EXPECT_EQ(CountAnswers(response, responseLen, Srp::RecordType::kSrv), 1);
}

TEST(TestInfraDnssd, DiscoveryProxyAnswersAaaaResolve)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0007", false, message), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(message.data(), message.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);

    uint8_t query[256];
    size_t queryLen = BuildQuery(query, sizeof(query), "HOST0007.default.service.arpa", Srp::RecordType::kAaaa);

    uint8_t response[512];
    size_t responseLen = 0;
    EXPECT_EQ(server.BuildQueryResponse(query, queryLen, response, sizeof(response), responseLen), Srp::ResponseCode::kNoError);
    ASSERT_GT(responseLen, 0u);
    EXPECT_EQ(CountAnswers(response, responseLen, Srp::RecordType::kAaaa), 1);
}

TEST(TestInfraDnssd, ServerEvictsExpiredLease)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    System::Clock::Internal::RAIIMockClock clock;
    clock.SetMonotonic(System::Clock::Milliseconds64(1000000));

    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t buffer[1600];
    MutableByteSpan message(buffer);
    // BuildTestUpdate uses a 3600 second lease.
    ASSERT_EQ(BuildTestUpdate(keyPair, "HOST0008", false, message), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(message.data(), message.size(), AddressFor("fe80::abcd")), Srp::ResponseCode::kNoError);
    ASSERT_EQ(server.GetRegisteredServiceCount(), 1);

    // Before the lease elapses the service is retained.
    clock.AdvanceMonotonic(System::Clock::Seconds32(3599));
    server.SweepExpired();
    EXPECT_EQ(server.GetRegisteredServiceCount(), 1);

    // After the lease elapses the service is evicted.
    clock.AdvanceMonotonic(System::Clock::Seconds32(2));
    server.SweepExpired();
    EXPECT_EQ(server.GetRegisteredServiceCount(), 0);
    EXPECT_GE(delegate.mRemoved, 1);
}

TEST(TestInfraDnssd, DiscoveryProxyUnknownNameReturnsNoAnswers)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);

    uint8_t query[256];
    size_t queryLen = BuildQuery(query, sizeof(query), "_matter._tcp.default.service.arpa", Srp::RecordType::kPtr);

    uint8_t response[512];
    size_t responseLen = 0;
    EXPECT_EQ(server.BuildQueryResponse(query, queryLen, response, sizeof(response), responseLen), Srp::ResponseCode::kNoError);
    ASSERT_GT(responseLen, 0u);
    EXPECT_EQ(CountAnswers(response, responseLen, Srp::RecordType::kPtr), 0);
}

// ---------------------------------------------------------------------------
// End-to-end loopback: client encodes an UPDATE, the server stores it, and the
// Discovery Proxy answers a query that decodes back to the registered values.
// This runs in a single process and needs no networking, so it is CI-friendly.
// ---------------------------------------------------------------------------

TEST(TestInfraDnssd, EndToEndClientServerDiscovery)
{
    ASSERT_EQ(chip::Platform::MemoryInit(), CHIP_NO_ERROR);
    Srp::SrpKeyPair keyPair;
    ASSERT_EQ(keyPair.InitEphemeral(), CHIP_NO_ERROR);

    // ---- Client side: build a signed registration UPDATE. ----
    Inet::IPAddress hostAddress = AddressFor("fe80::1234");
    const uint8_t siiValue[]    = { '3', '0', '0', '0' };
    TextEntry txt               = { "SII", siiValue, sizeof(siiValue) };

    Srp::ServiceDescriptor service;
    service.instanceLabel  = "AABBCCDD1122";
    service.serviceType    = "_matter._tcp";
    service.port           = 5540;
    service.textEntries    = &txt;
    service.textEntryCount = 1;

    Srp::UpdateParams params;
    params.transactionId = 0x4242;
    params.zone          = nullptr;
    params.hostLabel     = "HOSTE2E1";
    params.addresses     = Span<const Inet::IPAddress>(&hostAddress, 1);
    params.services      = Span<const Srp::ServiceDescriptor>(&service, 1);
    params.lease         = 3600;
    params.keyLease      = 7200;

    uint8_t updateBuf[1600];
    MutableByteSpan update(updateBuf);
    ASSERT_EQ(Srp::BuildRegisterUpdate(update, params, keyPair), CHIP_NO_ERROR);

    // ---- Server side: accept and store. ----
    InfraDnssdServerImpl server;
    CountingServerDelegate delegate;
    ASSERT_EQ(server.Init(&delegate), CHIP_NO_ERROR);
    ASSERT_EQ(server.ProcessUpdate(update.data(), update.size(), AddressFor("fe80::1234")), Srp::ResponseCode::kNoError);
    ASSERT_EQ(server.GetRegisteredServiceCount(), 1);

    // ---- Discovery Proxy: resolve the instance and decode the answer. ----
    uint8_t query[256];
    size_t queryLen =
        BuildQuery(query, sizeof(query), "AABBCCDD1122._matter._tcp.default.service.arpa", Srp::RecordType::kSrv);

    uint8_t response[512];
    size_t responseLen = 0;
    ASSERT_EQ(server.BuildQueryResponse(query, queryLen, response, sizeof(response), responseLen), Srp::ResponseCode::kNoError);
    ASSERT_GT(responseLen, 0u);

    Srp::DnsReader reader(response, responseLen);
    Srp::Header header;
    ASSERT_EQ(reader.ReadHeader(header), CHIP_NO_ERROR);
    for (uint16_t i = 0; i < header.qdcount; i++)
    {
        ASSERT_EQ(reader.SkipQuestion(), CHIP_NO_ERROR);
    }

    bool sawSrv           = false;
    bool sawAaaa          = false;
    bool sawTxt           = false;
    uint16_t resolvedPort = 0;
    Inet::IPAddress resolvedAddress;

    // DNS wire order is Answer, Authority, Additional — skip nscount before
    // reading AAAA records from the additional section.
    const uint32_t answerAndAuthority =
        static_cast<uint32_t>(header.ancount) + static_cast<uint32_t>(header.nscount);
    const uint32_t totalRecords = answerAndAuthority + static_cast<uint32_t>(header.arcount);
    for (uint32_t i = 0; i < totalRecords; i++)
    {
        Srp::DnsReader::RecordHeader rr;
        ASSERT_EQ(reader.ReadRecordHeader(rr), CHIP_NO_ERROR);
        const bool inAuthority = (i >= header.ancount && i < answerAndAuthority);
        if (inAuthority)
        {
            ASSERT_EQ(reader.SkipRecordData(rr), CHIP_NO_ERROR);
            continue;
        }
        if (rr.type == Srp::RecordType::kSrv)
        {
            uint16_t priority, weight, port;
            char target[Srp::kMaxDottedNameSize];
            ASSERT_EQ(reader.ReadSrv(priority, weight, port, target, sizeof(target)), CHIP_NO_ERROR);
            resolvedPort = port;
            sawSrv       = true;
        }
        else if (rr.type == Srp::RecordType::kAaaa)
        {
            ASSERT_EQ(reader.ReadAaaa(resolvedAddress), CHIP_NO_ERROR);
            sawAaaa = true;
        }
        else if (rr.type == Srp::RecordType::kTxt)
        {
            uint8_t txtData[Srp::kMaxParsedTxtSize];
            uint16_t rdlen = static_cast<uint16_t>(std::min<size_t>(rr.rdlength, sizeof(txtData)));
            ASSERT_EQ(reader.ReadBytes(txtData, rdlen), CHIP_NO_ERROR);
            // The TXT RDATA should contain the "SII=3000" character-string.
            const char expected[] = "SII=3000";
            for (uint16_t off = 0; off + 1 < rdlen;)
            {
                uint8_t len = txtData[off++];
                if (len == sizeof(expected) - 1 && memcmp(txtData + off, expected, len) == 0)
                {
                    sawTxt = true;
                }
                off = static_cast<uint16_t>(off + len);
            }
        }
        else
        {
            ASSERT_EQ(reader.SkipRecordData(rr), CHIP_NO_ERROR);
        }
    }

    EXPECT_TRUE(sawSrv);
    EXPECT_EQ(resolvedPort, 5540);
    EXPECT_TRUE(sawAaaa);
    EXPECT_TRUE(resolvedAddress == hostAddress);
    EXPECT_TRUE(sawTxt);
}

} // namespace
