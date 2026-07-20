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
 *   Concrete infrastructure DNS-SD server (SRP server + Advertising Proxy +
 *   Discovery Proxy) for Network Infrastructure Manager devices.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include <inet/IPAddress.h>
#include <inet/InetLayer.h>
#include <inet/UDPEndPoint.h>
#include <lib/core/CHIPError.h>
#include <lib/dnssd/InfraDnssdServer.h>
#include <lib/dnssd/SrpDnsMessage.h>
#include <lib/dnssd/SrpUpdate.h>
#include <system/SystemClock.h>
#include <system/SystemLayer.h>

namespace chip {
namespace Dnssd {

/// Default SRP server UDP port. Port 53 requires privileges; examples typically
/// use a high port and advertise it to clients via the provider record.
inline constexpr uint16_t kDefaultSrpServerPort = 53;

/// Maximum service lease the server will grant, in seconds. Requests for longer
/// leases are clamped and the granted value is echoed back to the client.
inline constexpr uint32_t kMaxGrantedLeaseSeconds = 7200; // 2 hours

/// Maximum key lease the server will grant, in seconds.
inline constexpr uint32_t kMaxGrantedKeyLeaseSeconds = 7 * 24 * 60 * 60; // 7 days

class InfraDnssdServerImpl : public InfraDnssdServer
{
public:
    InfraDnssdServerImpl()           = default;
    ~InfraDnssdServerImpl() override = default;

    InfraDnssdServerImpl(const InfraDnssdServerImpl &)             = delete;
    InfraDnssdServerImpl & operator=(const InfraDnssdServerImpl &) = delete;

    /// Provide the UDP endpoint manager used for the SRP/DNS listener.
    void SetEndPointManager(Inet::EndPointManager<Inet::UDPEndPoint> * manager) { mEndPointManager = manager; }

    /**
     * Enable the Advertising Proxy: re-advertise accepted SRP registrations via
     * the local mDNS stack so mDNS-only nodes can discover them. Requires the
     * platform DNS-SD stack to be initialized. Disabled by default.
     */
    void EnableAdvertisingProxy(bool enable) { mAdvertisingProxyEnabled = enable; }

    // InfraDnssdServer overrides.
    CHIP_ERROR Init(InfraDnssdServerDelegate * delegate) override;
    void Shutdown() override;
    CHIP_ERROR Start(uint16_t port = 0) override;
    CHIP_ERROR Stop() override;
    CHIP_ERROR SetAdvertiseInfraFlag(bool enable) override;
    bool IsRunning() const override { return mRunning; }
    uint16_t GetRegisteredServiceCount() const override;

    /// @return the port the server is listening on.
    uint16_t GetListenPort() const { return mListenPort; }

    // ------------------------------------------------------------------
    // Zone table access (used by the Advertising Proxy and Discovery Proxy).
    // ------------------------------------------------------------------

    static constexpr size_t kMaxHosts    = 16;
    static constexpr size_t kMaxServices = 32;

    struct HostRecord
    {
        bool inUse;
        char hostName[Srp::kMaxDottedNameSize];
        Inet::IPAddress addresses[Srp::kMaxParsedAddresses];
        size_t addressCount;
        uint8_t publicKey[Srp::kSrpPublicKeyRawSize];
        Inet::IPAddress clientAddress;
        System::Clock::Timestamp expiresAt;
    };

    struct ServiceRecord
    {
        bool inUse;
        char instanceName[Srp::kMaxDottedNameSize];
        char serviceType[Srp::kMaxDottedNameSize];
        char hostName[Srp::kMaxDottedNameSize];
        uint16_t port;
        uint8_t txt[Srp::kMaxParsedTxtSize];
        uint16_t txtLen;
        System::Clock::Timestamp expiresAt;
    };

    const ServiceRecord * Services() const { return mServices; }
    const HostRecord * Hosts() const { return mHosts; }
    const HostRecord * FindHost(const char * hostName) const;

    /**
     * Parse, authenticate (SIG(0)) and apply an SRP UPDATE message, returning the
     * DNS response code. Exposed (without networking) to enable unit testing and
     * single-process loopback integration.
     */
    Srp::ResponseCode ProcessUpdate(const uint8_t * message, size_t length, const Inet::IPAddress & clientAddress,
                                    uint32_t * grantedLease = nullptr, uint32_t * grantedKeyLease = nullptr);

    /**
     * Discovery Proxy: answer a unicast DNS query against the zone table. Encodes
     * the response into @a out and returns the response length via @a outLen.
     * Exposed (without networking) to enable unit testing and loopback.
     */
    Srp::ResponseCode BuildQueryResponse(const uint8_t * message, size_t length, uint8_t * out, size_t outSize, size_t & outLen);

    /// Run the lease-expiry sweep immediately (used by tests).
    void SweepExpired();

private:
    static void OnUdpMessageReceived(Inet::UDPEndPoint * endPoint, System::PacketBufferHandle && msg,
                                     const Inet::IPPacketInfo * pktInfo);
    static void OnUdpReceiveError(Inet::UDPEndPoint * endPoint, CHIP_ERROR error, const Inet::IPPacketInfo * pktInfo);
    static void OnLeaseSweepTimer(System::Layer * layer, void * context);

    void HandleMessage(const uint8_t * message, size_t length, const Inet::IPPacketInfo * pktInfo);
    void HandleUpdate(const uint8_t * message, size_t length, const Inet::IPPacketInfo * pktInfo);
    void HandleQuery(const uint8_t * message, size_t length, const Inet::IPPacketInfo * pktInfo);
    Srp::ResponseCode ApplyUpdate(const Srp::ParsedUpdate & update, const Inet::IPAddress & clientAddress,
                                  uint32_t & grantedLease, uint32_t & grantedKeyLease);
    // Send an UPDATE response. When @a rcode is kNoError the server echoes the
    // granted lease values in an EDNS Update Lease option so the client renews
    // on the accepted (not merely requested) schedule.
    void SendResponse(const Inet::IPPacketInfo * pktInfo, uint16_t transactionId, Srp::ResponseCode rcode, uint32_t grantedLease,
                      uint32_t grantedKeyLease);
    void SendRawResponse(const Inet::IPPacketInfo * pktInfo, const uint8_t * data, size_t length);
    void ScheduleSweep();

    HostRecord * FindHostMutable(const char * hostName);
    HostRecord * AllocateHost();
    ServiceRecord * FindService(const char * instanceName);
    ServiceRecord * AllocateService();
    void RemoveServicesForHost(const char * hostName);

    // Advertising Proxy: re-advertise a stored service via the local mDNS stack.
    void PublishViaMdns(const ServiceRecord & service);
    // Advertising Proxy: withdraw all mDNS records and re-publish the active set.
    void RepublishAllViaMdns();

    InfraDnssdServerDelegate * mDelegate                        = nullptr;
    Inet::EndPointManager<Inet::UDPEndPoint> * mEndPointManager = nullptr;
    Inet::EndPointHandle<Inet::UDPEndPoint> mUdpEndPoint;
    bool mRunning                 = false;
    bool mAdvertiseInfraFlag       = false;
    bool mAdvertisingProxyEnabled  = false;
    uint16_t mListenPort           = kDefaultSrpServerPort;
    bool mSweepScheduled           = false;

    HostRecord mHosts[kMaxHosts]          = {};
    ServiceRecord mServices[kMaxServices] = {};
};

} // namespace Dnssd
} // namespace chip
