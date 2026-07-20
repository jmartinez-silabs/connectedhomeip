/*
 *    Copyright (c) 2023 Project CHIP Authors
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

#include <AppMain.h>
#include <app/clusters/network-identity-management-server/AuthenticatorDriver.h>
#include <app/clusters/network-identity-management-server/DefaultNetworkIdentityStorage.h>
#include <app/clusters/network-identity-management-server/NetworkIdentityManagementCluster.h>
#include <app/clusters/network-identity-management-server/RawKeyNetworkIdentityKeystore.h>
#include <app/clusters/thread-border-router-management-server/thread-border-router-management-server.h>
#include <app/clusters/thread-network-directory-server/thread-network-directory-server.h>
#include <app/clusters/wifi-network-management-server/wifi-network-management-server.h>
#include <app/server-cluster/ServerClusterInterfaceRegistry.h>
#include <data-model-providers/codegen/CodegenDataModelProvider.h>
#include <lib/core/CHIPSafeCasts.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/Span.h>

#if MATTER_ENABLE_UBUS
#include "ThreadBROpenThreadUbus.h"
#include "UbusManager.h"
#else
#include "ThreadBRFake.h"
#endif

#ifndef CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER
#define CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER 0
#endif

#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER
#include <lib/dnssd/InfraDnssdServer.h>
#include <lib/dnssd/InfraDnssdServerImpl.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>
#endif

#include <optional>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;

#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER
namespace {

// High port so the NIM app does not need root privileges to bind (DNS port 53
// would). Clients learn the port from the infrastructure provider record.
constexpr uint16_t kSrpServerListenPort = 53538;

class LoggingSrpServerDelegate : public Dnssd::InfraDnssdServerDelegate
{
public:
    void OnServiceRegistered(const Inet::IPAddress & clientAddress, const char * hostName, const char * instanceName,
                             const char * serviceType, uint16_t port) override
    {
        char addr[Inet::IPAddress::kMaxStringLength] = {};
        clientAddress.ToString(addr);
        ChipLogProgress(AppServer, "SRP server: registered %s (%s) host %s port %u from %s", instanceName, serviceType,
                        hostName, port, addr);
    }

    void OnServiceRemoved(const char * instanceName, const char * serviceType) override
    {
        ChipLogProgress(AppServer, "SRP server: removed %s (%s)", instanceName, serviceType);
    }
};

LoggingSrpServerDelegate gSrpServerDelegate;
Dnssd::InfraDnssdServerImpl gInfraDnssdServer;

} // namespace
#endif // CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER

ByteSpan ByteSpanFromCharSpan(CharSpan span)
{
    return ByteSpan(Uint8::from_const_char(span.data()), span.size());
}

#if MATTER_ENABLE_UBUS
ubus::UbusManager gUbusManager{};
#endif

std::optional<DefaultThreadNetworkDirectoryServer> gThreadNetworkDirectoryServer;
void emberAfThreadNetworkDirectoryClusterInitCallback(EndpointId endpoint)
{
    VerifyOrDie(!gThreadNetworkDirectoryServer);
    TEMPORARY_RETURN_IGNORED gThreadNetworkDirectoryServer.emplace(endpoint).Init();
}

std::optional<WiFiNetworkManagementServer> gWiFiNetworkManagementServer;
void emberAfWiFiNetworkManagementClusterInitCallback(EndpointId endpoint)
{
    VerifyOrDie(!gWiFiNetworkManagementServer);
    TEMPORARY_RETURN_IGNORED gWiFiNetworkManagementServer.emplace(endpoint).Init();
}

std::optional<ThreadBorderRouterManagement::ServerInstance> gThreadBorderRouterManagementServer;
void emberAfThreadBorderRouterManagementClusterInitCallback(EndpointId endpoint)
{
    VerifyOrDie(!gThreadBorderRouterManagementServer);
#if MATTER_ENABLE_UBUS
    static OpenThreadUbusBorderRouterDelegate delegate{ gUbusManager };
#else
    static FakeBorderRouterDelegate delegate{};
#endif
    TEMPORARY_RETURN_IGNORED gThreadBorderRouterManagementServer
        .emplace(endpoint, &delegate, Server::GetInstance().GetFailSafeContext())
        .Init();
}

// Null AuthenticatorDriver for standalone testing (no real authenticator).
class NullAuthenticatorDriver : public NetworkIdentityManagement::AuthenticatorDriver
{
public:
    void OnStartup(NetworkIdentityManagement::AuthenticatorDriverCallback &, ReadOnlyNetworkIdentityStorage &) override {}
};

std::optional<DefaultNetworkIdentityStorage> gNetworkIdentityStorage;
Crypto::RawKeyNetworkIdentityKeystore gNetworkIdentityKeystore;
NullAuthenticatorDriver gNullAuthenticatorDriver;
LazyRegisteredServerCluster<NetworkIdentityManagementCluster> gNetworkIdentityManagementCluster;

void emberAfNetworkIdentityManagementClusterInitCallback(EndpointId endpoint)
{
    VerifyOrDie(!gNetworkIdentityManagementCluster.IsConstructed());
    gNetworkIdentityStorage.emplace(Server::GetInstance().GetPersistentStorage());
    gNetworkIdentityManagementCluster.Create(endpoint, *gNetworkIdentityStorage, gNetworkIdentityKeystore,
                                             gNullAuthenticatorDriver);
    SuccessOrDie(CodegenDataModelProvider::Instance().Registry().Register(gNetworkIdentityManagementCluster.Registration()));
}

static void ApplicationEarlyInit()
{
#if MATTER_ENABLE_UBUS
    SuccessOrDie(gUbusManager.Init());
#endif
}

void ApplicationInit()
{
    TEMPORARY_RETURN_IGNORED gWiFiNetworkManagementServer->SetNetworkCredentials(ByteSpanFromCharSpan("MatterAP"_span),
                                                                                 ByteSpanFromCharSpan("Setec Astronomy"_span));

#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER
    gInfraDnssdServer.SetEndPointManager(DeviceLayer::UDPEndPointManager());
    gInfraDnssdServer.EnableAdvertisingProxy(true);
    Dnssd::InfraDnssdServer::SetInstance(gInfraDnssdServer);
    if (gInfraDnssdServer.Init(&gSrpServerDelegate) != CHIP_NO_ERROR)
    {
        ChipLogError(AppServer, "Failed to initialize Infra SRP server");
    }
    else
    {
        CHIP_ERROR srpErr = gInfraDnssdServer.Start(kSrpServerListenPort);
        if (srpErr == CHIP_NO_ERROR)
        {
            (void) gInfraDnssdServer.SetAdvertiseInfraFlag(true);
            ChipLogProgress(AppServer, "Infra SRP server (NIM) listening on UDP port %u", kSrpServerListenPort);
        }
        else
        {
            ChipLogError(AppServer, "Failed to start Infra SRP server: %" CHIP_ERROR_FORMAT, srpErr.Format());
        }
    }
#endif // CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER
}

void ApplicationShutdown()
{
#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_SRP_SERVER
    gInfraDnssdServer.Shutdown();
#endif
#if MATTER_ENABLE_UBUS
    gUbusManager.Shutdown();
#endif
}

int main(int argc, char * argv[])
{
    VerifyOrReturnValue(ChipLinuxAppInit(argc, argv) == 0, -1);
    ApplicationEarlyInit();
    ChipLinuxAppMainLoop();
    return 0;
}
