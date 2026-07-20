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
 *   Unicast DNS resolver used by the SRP client to browse and resolve services
 *   through a Discovery Proxy over UDP (instead of multicast DNS).
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include <inet/IPAddress.h>
#include <inet/InetLayer.h>
#include <inet/UDPEndPoint.h>
#include <lib/core/CHIPError.h>
#include <lib/dnssd/platform/Dnssd.h>

namespace chip {
namespace Dnssd {
namespace Srp {

/// DNS domain used for unicast SRP browse/resolve queries.
inline constexpr char kUnicastDomain[] = "default.service.arpa";

/**
 * Send a unicast PTR browse query for @a type / @a protocol to the Discovery
 * Proxy at @a serverAddress:@a serverPort and dispatch discovered instances to
 * @a callback. The query context is released after the callback fires or on
 * timeout.
 */
CHIP_ERROR UnicastBrowse(Inet::EndPointManager<Inet::UDPEndPoint> * endPointManager, const char * type,
                         DnssdServiceProtocol protocol, Inet::IPAddressType addressType, Inet::InterfaceId interface,
                         const Inet::IPAddress & serverAddress, uint16_t serverPort, DnssdBrowseCallback callback,
                         void * context);

/**
 * Send a unicast SRV/TXT/AAAA resolve query for the service described by
 * @a service to the Discovery Proxy at @a serverAddress:@a serverPort and
 * dispatch the resolved record to @a callback.
 */
CHIP_ERROR UnicastResolve(Inet::EndPointManager<Inet::UDPEndPoint> * endPointManager, const DnssdService * service,
                          Inet::InterfaceId interface, const Inet::IPAddress & serverAddress, uint16_t serverPort,
                          DnssdResolveCallback callback, void * context);

} // namespace Srp
} // namespace Dnssd
} // namespace chip
