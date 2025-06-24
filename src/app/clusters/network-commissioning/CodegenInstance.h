/*
 *    Copyright (c) 2025 Project CHIP Authors
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
#pragma once

#include "NetworkCommissioningCluster.h"

#include <data-model-providers/codegen/CodegenDataModelProvider.h>
#include <data-model-providers/codegen/ServerClusterInterfaceRegistry.h>

namespace chip {
namespace app {
namespace Clusters {
namespace NetworkCommissioning {

/// Automates integration of a NetworkCommissioningCluster
/// with the CodegenDataModelInterface.
///
/// This class exists as a compatibility layer with the original
/// network-commissioning class, however it only exposes Init/Shutdown and
/// relevant constructors
class Instance
{
public:
    using WiFiDriver     = DeviceLayer::NetworkCommissioning::WiFiDriver;
    using ThreadDriver   = DeviceLayer::NetworkCommissioning::ThreadDriver;
    using EthernetDriver = DeviceLayer::NetworkCommissioning::EthernetDriver;

    // Init and Shutdown are implemented here to avoid needing explicit template declaration for all possible TransportDriver
    CHIP_ERROR Init()
    {
        ReturnErrorOnFailure(mCluster.Cluster().Init());
        return CodegenDataModelProvider::Instance().Registry().Register(mCluster.Registration());
    }

    void Shutdown()
    {
        CodegenDataModelProvider::Instance().Registry().Unregister(&mCluster.Cluster());
        mCluster.Cluster().Shutdown();
    }

    Instance(EndpointId aEndpointId, WiFiDriver * apDelegate) : mCluster(aEndpointId, apDelegate) {}
    Instance(EndpointId aEndpointId, ThreadDriver * apDelegate) : mCluster(aEndpointId, apDelegate) {}
    Instance(EndpointId aEndpointId, EthernetDriver * apDelegate) : mCluster(aEndpointId, apDelegate) {}

private:
    RegisteredServerCluster<NetworkCommissioningCluster> mCluster;
};

// The FullInstance class encapsulates the creation and management of a transport driver instance (Wifi,Thread or Ethernet)
// together with a NetworkCommissioningCluster instance.
// It provides a unified interface to initialize, configure, and operate both components,
// ensuring they are properly linked for network commissioning operations. This class simplifies the integration process by handling
// the instantiation and lifecycle of both the transport driver and the cluster as a single unit.
template <typename TransportDriver>
class FullInstance : public Instance
{
public:
    FullInstance(EndpointId aEndpointId) : Instance(aEndpointId, &mDriver) {}

    TransportDriver & GetDriver() { return mDriver; }

private:
    TransportDriver mDriver;
};
} // namespace NetworkCommissioning
} // namespace Clusters
} // namespace app
} // namespace chip
