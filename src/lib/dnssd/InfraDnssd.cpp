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

#include "InfraDnssd.h"

#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>

namespace chip {
namespace Dnssd {

namespace {
InfraDnssdManager sInstance;
} // namespace

InfraDnssdManager & InfraDnssdManager::Instance()
{
    return sInstance;
}

CHIP_ERROR InfraDnssdManager::Init(InfraProviderDelegate * delegate)
{
    VerifyOrReturnError(delegate != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(!mInitialized, CHIP_ERROR_INCORRECT_STATE);

    mDelegate    = delegate;
    mInitialized = true;

    ChipLogProgress(Discovery, "InfraDnssdManager initialized");
    return CHIP_NO_ERROR;
}

void InfraDnssdManager::Shutdown()
{
    if (!mInitialized)
    {
        return;
    }

    mDelegate        = nullptr;
    mCurrentProvider = {};
    mInitialized     = false;

    ChipLogProgress(Discovery, "InfraDnssdManager shut down");
}

bool InfraDnssdManager::HasProvider() const
{
    return mCurrentProvider.type != InfraProviderType::kNone;
}

const InfraProvider & InfraDnssdManager::GetCurrentProvider() const
{
    return mCurrentProvider;
}

CHIP_ERROR InfraDnssdManager::RegisterService(const DnssdService & service)
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(HasProvider(), CHIP_ERROR_NOT_CONNECTED);

    // TODO: Implement SRP DNS UPDATE to register service with the current provider.
    // The SRP client should construct a DNS UPDATE message per RFC 9665 containing:
    // - The service SRV record (instance name, service type, port)
    // - The service TXT record (text entries)
    // - The host AAAA record(s) (IPv6 addresses)
    // - A signature over the update using the device's SRP key pair
    //
    // For the initial implementation, consider using Apple's mDNSResponder
    // ServiceRegistration library or implementing a minimal SRP client.

    ChipLogProgress(Discovery, "InfraDnssd: RegisterService %s.%s port %u (provider %s:%u)", service.mName, service.mType,
                    service.mPort, "SRP", mCurrentProvider.port);

    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR InfraDnssdManager::RemoveService(const char * instanceName, const char * serviceType)
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(HasProvider(), CHIP_ERROR_NOT_CONNECTED);

    // TODO: Implement SRP service removal.

    ChipLogProgress(Discovery, "InfraDnssd: RemoveService %s %s", instanceName, serviceType);

    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR InfraDnssdManager::RemoveAllServices()
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);

    if (!HasProvider())
    {
        return CHIP_NO_ERROR;
    }

    // TODO: Remove all SRP registrations.

    ChipLogProgress(Discovery, "InfraDnssd: RemoveAllServices");

    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR InfraDnssdManager::FinalizeServiceUpdate()
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);

    if (!HasProvider())
    {
        return CHIP_NO_ERROR;
    }

    // TODO: Commit pending SRP updates to the server.

    ChipLogProgress(Discovery, "InfraDnssd: FinalizeServiceUpdate");

    return CHIP_ERROR_NOT_IMPLEMENTED;
}

void InfraDnssdManager::OnRouterAdvertisementReceived(const Inet::IPAddress & sourceAddress, uint16_t routerLifetime,
                                                      bool hasInfraFlag, bool hasSnacFlag)
{
    if (!mInitialized)
    {
        return;
    }

    InfraProvider candidate;
    candidate.address = sourceAddress;
    candidate.port    = 53; // Default DNS port; SRP port may be discovered from RA option

    if (hasInfraFlag && routerLifetime > 0)
    {
        candidate.type = InfraProviderType::kInfraRouter;
        ChipLogProgress(Discovery, "InfraDnssd: Discovered Infrastructure Router via RA");
    }
    else if (hasSnacFlag)
    {
        candidate.type = InfraProviderType::kSnacRouter;
        ChipLogProgress(Discovery, "InfraDnssd: Discovered SNAC Router via RA");
    }
    else
    {
        return;
    }

    UpdatePreferredProvider(candidate);
}

void InfraDnssdManager::OnAdHocProviderDiscovered(const Inet::IPAddress & address, uint16_t port)
{
    if (!mInitialized)
    {
        return;
    }

    InfraProvider candidate;
    candidate.type    = InfraProviderType::kAdHocProvider;
    candidate.address = address;
    candidate.port    = port;

    ChipLogProgress(Discovery, "InfraDnssd: Discovered Ad-hoc SRP provider via mDNS");

    UpdatePreferredProvider(candidate);
}

void InfraDnssdManager::OnProviderUnreachable()
{
    if (!mInitialized)
    {
        return;
    }

    ChipLogProgress(Discovery, "InfraDnssd: Current provider unreachable, resetting");

    mCurrentProvider = {};

    if (mDelegate != nullptr)
    {
        mDelegate->OnInfraProviderLost();
    }
}

void InfraDnssdManager::UpdatePreferredProvider(const InfraProvider & candidate)
{
    // Lower enum value = higher priority
    if (candidate.type < mCurrentProvider.type || mCurrentProvider.type == InfraProviderType::kNone)
    {
        mCurrentProvider = candidate;

        ChipLogProgress(Discovery, "InfraDnssd: Provider updated to type %u", static_cast<unsigned>(candidate.type));

        if (mDelegate != nullptr)
        {
            mDelegate->OnInfraProviderAvailable(mCurrentProvider);
        }
    }
}

} // namespace Dnssd
} // namespace chip
