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
#include <inet/InetLayer.h>
#include <inet/UDPEndPoint.h>
#include <lib/core/CHIPError.h>
#include <lib/core/CHIPPersistentStorageDelegate.h>
#include <lib/dnssd/Constants.h>
#include <lib/dnssd/SrpKeyPair.h>
#include <lib/dnssd/SrpUpdate.h>
#include <lib/dnssd/platform/Dnssd.h>
#include <lib/support/Span.h>
#include <system/SystemLayer.h>

namespace chip {
namespace Dnssd {

/// Maximum encoded SRP UPDATE message size the client will produce.
inline constexpr size_t kMaxSrpMessageSize = 1600;

/**
 * Types of infrastructure DNS-SD service providers, ordered by priority (highest first).
 */
enum class InfraProviderType : uint8_t
{
    kNone          = 0, ///< No provider available
    kInfraRouter   = 1, ///< Infrastructure router (CE router) - highest priority
    kSnacRouter    = 2, ///< SNAC router (e.g., OTBR)
    kAdHocProvider = 3, ///< Ad-hoc provider discovered via mDNS
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
     * @param delegate  Delegate to receive provider discovery events.
     * @return CHIP_NO_ERROR on success.
     */
    CHIP_ERROR Init(InfraProviderDelegate * delegate);

    /**
     * Shut down the infrastructure DNS-SD manager and release resources.
     */
    void Shutdown();

    // ------------------------------------------------------------------
    // Configuration (set before registering services).
    // ------------------------------------------------------------------

    /// Provide the UDP endpoint manager and system layer used for SRP transport.
    void SetEndPointManager(Inet::EndPointManager<Inet::UDPEndPoint> * manager) { mEndPointManager = manager; }

    /// Provide persistent storage for the SRP host key.
    void SetStorage(PersistentStorageDelegate * storage) { mStorage = storage; }

    /// Set the host label (single DNS label) used for the SRP host name.
    CHIP_ERROR SetHostLabel(const char * hostLabel);

    /// Set the host IPv6 addresses advertised in AAAA records.
    CHIP_ERROR SetHostAddresses(Span<const Inet::IPAddress> addresses);

    /// Set the service/key lease durations, in seconds.
    void SetLease(uint32_t leaseSeconds, uint32_t keyLeaseSeconds)
    {
        mLease    = leaseSeconds;
        mKeyLease = keyLeaseSeconds;
    }

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
     * Register (queue) a DNS-SD service for SRP registration with the current
     * infrastructure provider. The actual DNS UPDATE is sent by
     * FinalizeServiceUpdate().
     *
     * @return CHIP_ERROR_NOT_CONNECTED if no provider is available (the caller
     *         should fall back to mDNS).
     */
    CHIP_ERROR RegisterService(const DnssdService & service);

    /**
     * Queue removal of a previously registered service.
     */
    CHIP_ERROR RemoveService(const char * instanceName, const char * serviceType);

    /**
     * Queue removal of all registered services.
     */
    CHIP_ERROR RemoveAllServices();

    /**
     * Send the pending service registration state to the SRP server as a single
     * signed DNS UPDATE.
     */
    CHIP_ERROR FinalizeServiceUpdate();

    /// @return the number of services currently queued/registered.
    size_t GetServiceCount() const;

    // ------------------------------------------------------------------
    // Provider discovery events (called by the platform layer).
    // ------------------------------------------------------------------

    void OnRouterAdvertisementReceived(const Inet::IPAddress & sourceAddress, uint16_t routerLifetime, bool hasInfraFlag,
                                       bool hasSnacFlag);
    void OnAdHocProviderDiscovered(const Inet::IPAddress & address, uint16_t port);
    void OnProviderUnreachable();

    InfraDnssdManager()  = default;
    ~InfraDnssdManager() = default;

    InfraDnssdManager(const InfraDnssdManager &)             = delete;
    InfraDnssdManager & operator=(const InfraDnssdManager &) = delete;

private:
    static constexpr size_t kMaxTextKeySize   = 32;
    static constexpr size_t kMaxTextValueSize = 128;

    // Text entry stored alongside a queued service.
    struct StoredTextEntry
    {
        char key[kMaxTextKeySize];
        uint8_t value[kMaxTextValueSize];
        uint16_t valueLen;
        bool hasValue;
    };

    static constexpr size_t kMaxTextEntriesPerService = 12;
    static constexpr size_t kMaxServiceTypeSize       = 48;
    static constexpr size_t kMaxHostAddresses         = 4;
    static constexpr size_t kHostLabelMaxSize         = 64;

    // Per-service registration state. Because the whole service set is sent in a
    // single signed UPDATE (and the server upserts per service), only three
    // states are needed: a free slot, a service that should be present, and a
    // service pending removal (its delete records are sent, then the slot is
    // freed once the server acknowledges).
    enum class ServiceState : uint8_t
    {
        kFree = 0, ///< Unused slot.
        kActive,   ///< Desired present; asserted in every UPDATE.
        kToRemove, ///< Desired absent; a delete is sent, freed once acked.
    };

    struct ServiceEntry
    {
        ServiceState state;
        char instanceLabel[Common::kInstanceNameMaxLength + 1];
        char serviceType[kMaxServiceTypeSize];
        uint16_t port;
        StoredTextEntry textEntries[kMaxTextEntriesPerService];
        size_t textEntryCount;
    };

    // Retry/backoff parameters (milliseconds). Those values have been copied from OpenThread's SRP client:
    // wait for a response, then retry with an exponentially growing, jittered
    // interval so a lost or rejected UPDATE is eventually re-sent.
    static constexpr uint32_t kResponseTimeoutMs      = 3000;
    static constexpr uint32_t kMinRetryWaitMs         = 1800;
    static constexpr uint32_t kMaxRetryWaitMs         = 3600u * 1000u; // 1 hour
    static constexpr uint32_t kRetryGrowthNumerator   = 17;            // 1.7x growth
    static constexpr uint32_t kRetryGrowthDenominator = 10;
    static constexpr uint32_t kRetryJitterMs          = 500;
    // Guard interval subtracted from the granted lease to renew early.
    static constexpr uint32_t kRenewGuardSeconds = 120;
    // After this many consecutive failures the current provider is dropped so
    // the device can fail over to another provider or fall back to mDNS.
    static constexpr uint8_t kMaxConsecutiveFailures = 3;

    void UpdatePreferredProvider(const InfraProvider & candidate);
    CHIP_ERROR EnsureKeyPair();
    // Populate mHostAddresses from the device's network interfaces (global and
    // unique-local IPv6 addresses), used when addresses were not set explicitly.
    void CollectHostAddresses();
    // Encode the current desired state (active services as adds, kToRemove as
    // deletes; or a whole-host removal) and send it, arming the response timer.
    CHIP_ERROR SendUpdate(bool removeHost);
    // Request a send of the current desired state, coalescing with any update
    // already in flight.
    CHIP_ERROR RequestSend(bool removeHost);
    CHIP_ERROR SendMessage(const uint8_t * data, size_t length);
    // Commit local state after the server accepts an UPDATE.
    void OnUpdateAccepted(uint32_t grantedLease, uint32_t grantedKeyLease);
    // Handle a rejected UPDATE, timeout, or send error: back off and retry, or
    // drop the provider after too many failures.
    void OnUpdateFailed(const char * reason);
    void ScheduleRenewal(uint32_t leaseSeconds);
    void ArmResponseTimeout();
    void CancelTimers();
    // Fill SIG(0) inception/expiration from the real-time clock when available.
    void PopulateSig0Window(Srp::UpdateParams & params) const;
    ServiceEntry * FindService(const char * instanceLabel, const char * serviceType);
    ServiceEntry * AllocateService();
    size_t CollectActive(Srp::ServiceDescriptor * descriptors, TextEntry (*textEntries)[kMaxTextEntriesPerService],
                         size_t maxServices, bool includeRemovals) const;

    static void OnRenewalTimer(System::Layer * layer, void * context);
    static void OnResponseTimeoutTimer(System::Layer * layer, void * context);
    static void OnRetryTimer(System::Layer * layer, void * context);
    static void OnUdpMessageReceived(Inet::UDPEndPoint * endPoint, System::PacketBufferHandle && msg,
                                     const Inet::IPPacketInfo * pktInfo);
    static void OnUdpReceiveError(Inet::UDPEndPoint * endPoint, CHIP_ERROR error, const Inet::IPPacketInfo * pktInfo);

    InfraProviderDelegate * mDelegate = nullptr;
    InfraProvider mCurrentProvider    = {};
    bool mInitialized                 = false;

    // SRP client configuration/state.
    Inet::EndPointManager<Inet::UDPEndPoint> * mEndPointManager = nullptr;
    Inet::EndPointHandle<Inet::UDPEndPoint> mUdpEndPoint;
    PersistentStorageDelegate * mStorage = nullptr;
    Srp::SrpKeyPair mKeyPair;
    bool mKeyPairReady = false;

    char mHostLabel[kHostLabelMaxSize] = "";
    bool mHostLabelSet                 = false;
    Inet::IPAddress mHostAddresses[kMaxHostAddresses];
    size_t mHostAddressCount    = 0;
    bool mHostAddressesExplicit = false;

    ServiceEntry mServices[CHIP_DEVICE_CONFIG_WIFI_SRP_MAX_SERVICES] = {};

    uint32_t mLease         = 7200;   // requested service lease, 2 hours
    uint32_t mKeyLease      = 604800; // requested key lease, 7 days
    uint16_t mTransactionId = 0;

    // In-flight update tracking and retry state.
    bool mUpdateInFlight         = false;
    bool mInFlightIsRemoveHost   = false;
    bool mResendPending          = false;
    bool mResendIsRemoveHost     = false;
    uint16_t mInFlightTxnId      = 0;
    uint32_t mRetryWaitMs        = kMinRetryWaitMs;
    uint8_t mConsecutiveFailures = 0;

    bool mRenewalScheduled  = false;
    bool mResponseScheduled = false;
    bool mRetryScheduled    = false;
};

} // namespace Dnssd
} // namespace chip
