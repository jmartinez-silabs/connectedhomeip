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

/**
 * @file
 *   Infrastructure DNS-SD manager for Wi-Fi and Ethernet devices.
 *
 *   Manages discovery of infrastructure DNS-SD service providers (SRP servers)
 *   and routes service registrations through SRP when a provider is available,
 *   falling back to Multicast DNS otherwise.
 *
 *   Infrastructure providers are discovered via:
 *   - IPv6 Router Advertisements with DNS-SD infrastructure flags
 *   - mDNS browse for _dns-sd-srp._tcp ad-hoc service providers
 *
 *   See Matter Core Specification, Discovery section "DNS-SD on Infrastructure
 *   for Wi-Fi and Ethernet" for normative requirements.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include <inet/IPAddress.h>
#include <lib/core/CHIPError.h>
#include <lib/dnssd/platform/Dnssd.h>
#include <lib/support/Span.h>

namespace chip {
namespace Dnssd {

/**
 * Types of infrastructure DNS-SD service providers, ordered by priority (highest first).
 */
enum class InfraProviderType : uint8_t
{
    kNone              = 0, ///< No provider available
    kInfraRouter       = 1, ///< Infrastructure router (CE router) - highest priority
    kSnacRouter        = 2, ///< SNAC router (e.g., OTBR)
    kAdHocProvider     = 3, ///< Ad-hoc provider discovered via mDNS
};

/**
 * Describes a discovered infrastructure DNS-SD service provider.
 */
struct InfraProvider
{
    InfraProviderType type;
    Inet::IPAddress address;
    uint16_t port;
};

/**
 * Delegate interface for receiving infrastructure provider discovery events.
 */
class InfraProviderDelegate
{
public:
    virtual ~InfraProviderDelegate() = default;

    /**
     * Called when an infrastructure DNS-SD service provider is discovered or when
     * the preferred provider changes.
     */
    virtual void OnInfraProviderAvailable(const InfraProvider & provider) = 0;

    /**
     * Called when the current infrastructure provider becomes unreachable.
     */
    virtual void OnInfraProviderLost() = 0;
};

/**
 * Manages the lifecycle of infrastructure DNS-SD for Wi-Fi and Ethernet devices.
 *
 * Responsibilities:
 * - Discover infrastructure providers via RA processing and mDNS browse
 * - Maintain the current preferred provider based on priority
 * - Provide an SRP client that registers services with the preferred provider
 * - Fall back to mDNS when no provider is available
 */
class InfraDnssdManager
{
public:
    static InfraDnssdManager & Instance();

    /**
     * Initialize the infrastructure DNS-SD manager.
     *
     * Begins listening for Router Advertisements and optionally browsing
     * for ad-hoc SRP service providers via mDNS.
     *
     * @param delegate  Delegate to receive provider discovery events.
     * @return CHIP_NO_ERROR on success.
     */
    CHIP_ERROR Init(InfraProviderDelegate * delegate);

    /**
     * Shut down the infrastructure DNS-SD manager and release resources.
     */
    void Shutdown();

    /**
     * @return true if an infrastructure provider is currently available.
     */
    bool HasProvider() const;

    /**
     * @return the currently selected infrastructure provider, or a provider
     *         with type kNone if no provider is available.
     */
    const InfraProvider & GetCurrentProvider() const;

    /**
     * Register a DNS-SD service with the current infrastructure provider via SRP.
     *
     * If no provider is available, returns CHIP_ERROR_NOT_CONNECTED.
     * The caller should fall back to mDNS in that case.
     *
     * @param service  The service to register.
     * @return CHIP_NO_ERROR on success, or an error if registration failed.
     */
    CHIP_ERROR RegisterService(const DnssdService & service);

    /**
     * Remove a previously registered service from the SRP server.
     *
     * @param instanceName  The instance name of the service to remove.
     * @param serviceType   The service type string (e.g., "_matter._tcp").
     * @return CHIP_NO_ERROR on success.
     */
    CHIP_ERROR RemoveService(const char * instanceName, const char * serviceType);

    /**
     * Remove all registered services from the SRP server.
     *
     * @return CHIP_NO_ERROR on success.
     */
    CHIP_ERROR RemoveAllServices();

    /**
     * Commit pending service registration changes to the SRP server.
     *
     * @return CHIP_NO_ERROR on success.
     */
    CHIP_ERROR FinalizeServiceUpdate();

    /**
     * Notify the manager that a Router Advertisement has been received.
     * Called by the platform networking layer when an RA is processed.
     *
     * @param sourceAddress   The IPv6 source address of the RA.
     * @param routerLifetime  The Router Lifetime field from the RA.
     * @param hasInfraFlag    True if the DNS-SD infrastructure flag is set.
     * @param hasSnacFlag     True if the SNAC Router flag is set.
     */
    void OnRouterAdvertisementReceived(const Inet::IPAddress & sourceAddress, uint16_t routerLifetime, bool hasInfraFlag,
                                       bool hasSnacFlag);

    /**
     * Notify the manager that an ad-hoc SRP provider was discovered via mDNS.
     *
     * @param address  The IPv6 address of the ad-hoc provider.
     * @param port     The port of the SRP service.
     */
    void OnAdHocProviderDiscovered(const Inet::IPAddress & address, uint16_t port);

    /**
     * Notify the manager that the current provider has become unreachable
     * (e.g., SRP registration or renewal failure).
     */
    void OnProviderUnreachable();

    InfraDnssdManager()  = default;
    ~InfraDnssdManager() = default;

    InfraDnssdManager(const InfraDnssdManager &)             = delete;
    InfraDnssdManager & operator=(const InfraDnssdManager &) = delete;

private:
    void UpdatePreferredProvider(const InfraProvider & candidate);

    InfraProviderDelegate * mDelegate = nullptr;
    InfraProvider mCurrentProvider    = {};
    bool mInitialized                 = false;
};

} // namespace Dnssd
} // namespace chip
