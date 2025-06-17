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
template <typename TransportDriver>
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

    Instance(EndpointId aEndpointId) : Instance(aEndpointId, &mDriver) {}

    TransportDriver & GetDriver() { return mDriver; }

private:
    TransportDriver mDriver;
    RegisteredServerCluster<NetworkCommissioningCluster> mCluster;
};

} // namespace NetworkCommissioning
} // namespace Clusters
} // namespace app
} // namespace chip
