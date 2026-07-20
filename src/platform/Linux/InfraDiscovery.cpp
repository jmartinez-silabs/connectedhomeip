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
 *   Linux implementation of infrastructure DNS-SD provider discovery.
 *
 *   Two discovery paths are provided:
 *   - An ICMPv6 Router Advertisement listener that reports the router lifetime
 *     and the infrastructure / SNAC flags to the InfraDnssdManager.
 *   - An ad-hoc mDNS browse for _dns-sd-srp._tcp providers, which resolves each
 *     provider and reports its address/port. This is the primary bring-up path
 *     since RA reception typically requires elevated privileges.
 */

#include <lib/dnssd/platform/InfraDiscovery.h>

#include <cerrno>
#include <cstring>
#include <unistd.h>

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <lib/dnssd/InfraDnssd.h>
#include <lib/dnssd/platform/Dnssd.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>
#include <system/SocketEvents.h>

namespace chip {
namespace Dnssd {

namespace {

// Reserved Router Advertisement flag bits used to signal that the router offers
// DNS-SD infrastructure (SRP) service. The exact bit assignment is deployment
// specific and should be aligned with the final Matter infrastructure discovery
// specification; the mapping is isolated here so it can be adjusted in one place.
constexpr uint8_t kRaFlagInfra = 0x01;
constexpr uint8_t kRaFlagSnac  = 0x02;

int sRaSocket                              = -1;
System::SocketWatchToken sRaWatch          = 0;
bool sAdHocBrowseActive                    = false;
intptr_t sAdHocBrowseId                    = 0;

void OnRaSocketEvent(System::SocketEvents events, intptr_t data)
{
    VerifyOrReturn(events.Has(System::SocketEventFlags::kRead) && sRaSocket >= 0);

    uint8_t buffer[1280];
    struct sockaddr_in6 from = {};
    socklen_t fromLen        = sizeof(from);
    ssize_t received = recvfrom(sRaSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&from), &fromLen);
    VerifyOrReturn(received >= static_cast<ssize_t>(sizeof(struct nd_router_advert)));

    const auto * ra = reinterpret_cast<const struct nd_router_advert *>(buffer);
    if (ra->nd_ra_type != ND_ROUTER_ADVERT)
    {
        return;
    }

    uint16_t routerLifetime = ntohs(ra->nd_ra_router_lifetime);
    uint8_t flags           = ra->nd_ra_flags_reserved;
    bool hasInfraFlag       = (flags & kRaFlagInfra) != 0;
    bool hasSnacFlag        = (flags & kRaFlagSnac) != 0;

    Inet::IPAddress source = Inet::IPAddress::FromSockAddr(from);

    InfraDnssdManager::Instance().OnRouterAdvertisementReceived(source, routerLifetime, hasInfraFlag, hasSnacFlag);
}

void OnAdHocResolve(void * context, DnssdService * result, const Span<Inet::IPAddress> & addresses, CHIP_ERROR error)
{
    VerifyOrReturn(error == CHIP_NO_ERROR && result != nullptr && !addresses.empty());
    InfraDnssdManager::Instance().OnAdHocProviderDiscovered(addresses.front(), result->mPort);
}

void OnAdHocBrowse(void * context, DnssdService * services, size_t servicesSize, bool finalBrowse, CHIP_ERROR error)
{
    if (error != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "Infra ad-hoc browse failed: %" CHIP_ERROR_FORMAT, error.Format());
        return;
    }
    for (size_t i = 0; i < servicesSize; i++)
    {
        LogErrorOnFailure(ChipDnssdResolve(&services[i], services[i].mInterface, OnAdHocResolve, nullptr));
    }
}

} // namespace

CHIP_ERROR ChipInfraDiscoveryStartRaListener()
{
    VerifyOrReturnError(sRaSocket < 0, CHIP_NO_ERROR);

    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0)
    {
        // Typically requires CAP_NET_RAW/root. Degrade gracefully: the ad-hoc
        // mDNS browse remains available for provider discovery.
        ChipLogProgress(Discovery, "Infra RA listener unavailable (socket: %s); relying on ad-hoc browse", strerror(errno));
        return CHIP_NO_ERROR;
    }

    // Only deliver Router Advertisements to this socket.
    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
    if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) != 0)
    {
        ChipLogError(Discovery, "Infra RA listener: failed to set ICMP6 filter: %s", strerror(errno));
        close(fd);
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR err = DeviceLayer::SystemLayerSockets().StartWatchingSocket(fd, &sRaWatch);
    if (err == CHIP_NO_ERROR)
    {
        err = DeviceLayer::SystemLayerSockets().SetCallback(sRaWatch, OnRaSocketEvent, 0);
    }
    if (err == CHIP_NO_ERROR)
    {
        err = DeviceLayer::SystemLayerSockets().RequestCallbackOnPendingRead(sRaWatch);
    }
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "Infra RA listener: failed to watch socket: %" CHIP_ERROR_FORMAT, err.Format());
        close(fd);
        return err;
    }

    sRaSocket = fd;
    ChipLogProgress(Discovery, "Infra RA listener started");
    return CHIP_NO_ERROR;
}

void ChipInfraDiscoveryStopRaListener()
{
    VerifyOrReturn(sRaSocket >= 0);
    TEMPORARY_RETURN_IGNORED DeviceLayer::SystemLayerSockets().StopWatchingSocket(&sRaWatch);
    close(sRaSocket);
    sRaSocket = -1;
}

CHIP_ERROR ChipInfraDiscoveryStartAdHocBrowse()
{
    VerifyOrReturnError(!sAdHocBrowseActive, CHIP_NO_ERROR);

    CHIP_ERROR err = ChipDnssdBrowse("_dns-sd-srp", DnssdServiceProtocol::kDnssdProtocolTcp, Inet::IPAddressType::kIPv6,
                                     Inet::InterfaceId::Null(), OnAdHocBrowse, nullptr, &sAdHocBrowseId);
    ReturnErrorOnFailure(err);
    sAdHocBrowseActive = true;
    ChipLogProgress(Discovery, "Infra ad-hoc SRP provider browse started");
    return CHIP_NO_ERROR;
}

void ChipInfraDiscoveryStopAdHocBrowse()
{
    VerifyOrReturn(sAdHocBrowseActive);
    TEMPORARY_RETURN_IGNORED ChipDnssdStopBrowse(sAdHocBrowseId);
    sAdHocBrowseActive = false;
}

} // namespace Dnssd
} // namespace chip
