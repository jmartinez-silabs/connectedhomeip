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
 *   Infrastructure DNS-SD server interface for Network Infrastructure Manager devices.
 *
 *   Defines the abstract interface for an SRP server, Advertising Proxy,
 *   and Discovery Proxy that NIM devices must implement.
 *
 *   The SRP server accepts service registrations from Wi-Fi/Ethernet devices
 *   via the Service Registration Protocol (RFC 9665).
 *   The Advertising Proxy re-advertises registered services via mDNS.
 *   The Discovery Proxy responds to unicast DNS queries for local services.
 */

#pragma once

#include <cstdint>

#include <inet/IPAddress.h>
#include <lib/core/CHIPError.h>

namespace chip {
namespace Dnssd {

/**
 * Delegate for SRP server events.
 */
class InfraDnssdServerDelegate
{
public:
    virtual ~InfraDnssdServerDelegate() = default;

    /**
     * Called when a client registers or updates a service via SRP.
     *
     * @param clientAddress  The IPv6 address of the registering client.
     * @param hostName       The registered hostname.
     * @param instanceName   The service instance name.
     * @param serviceType    The service type (e.g., "_matter._tcp").
     * @param port           The service port.
     */
    virtual void OnServiceRegistered(const Inet::IPAddress & clientAddress, const char * hostName, const char * instanceName,
                                     const char * serviceType, uint16_t port) = 0;

    /**
     * Called when a client removes a service registration.
     */
    virtual void OnServiceRemoved(const char * instanceName, const char * serviceType) = 0;
};

/**
 * Abstract interface for the infrastructure DNS-SD server functionality
 * required by Network Infrastructure Manager devices.
 *
 * Implementations should provide:
 * - An SRP server (RFC 9665) that accepts service registrations
 * - An Advertising Proxy that re-advertises registrations via mDNS
 * - A Discovery Proxy (RFC 8766) for unicast DNS queries
 * - IPv6 RA advertisement of infrastructure DNS-SD availability
 */
class InfraDnssdServer
{
public:
    virtual ~InfraDnssdServer() = default;

    /**
     * Initialize the SRP server, Advertising Proxy, and Discovery Proxy.
     *
     * @param delegate  Delegate for server events (may be nullptr).
     * @return CHIP_NO_ERROR on success.
     */
    virtual CHIP_ERROR Init(InfraDnssdServerDelegate * delegate) = 0;

    /**
     * Shut down the server and release resources.
     */
    virtual void Shutdown() = 0;

    /**
     * Start the SRP server, listening for registration requests.
     *
     * @param port  The port to listen on for SRP requests. Use 0 for default (53).
     * @return CHIP_NO_ERROR on success.
     */
    virtual CHIP_ERROR Start(uint16_t port = 0) = 0;

    /**
     * Stop the SRP server.
     */
    virtual CHIP_ERROR Stop() = 0;

    /**
     * Enable or disable advertisement of the DNS-SD infrastructure flag
     * in IPv6 Router Advertisements.
     *
     * @param enable  True to enable RA flag advertisement.
     * @return CHIP_NO_ERROR on success.
     */
    virtual CHIP_ERROR SetAdvertiseInfraFlag(bool enable) = 0;

    /**
     * @return true if the SRP server is currently running.
     */
    virtual bool IsRunning() const = 0;

    /**
     * @return the number of currently registered services.
     */
    virtual uint16_t GetRegisteredServiceCount() const = 0;

    /**
     * Get the singleton instance of the InfraDnssdServer.
     * The actual implementation is platform-specific.
     */
    static InfraDnssdServer & Instance();
    static void SetInstance(InfraDnssdServer & server);

private:
    static InfraDnssdServer * sInstance;
};

} // namespace Dnssd
} // namespace chip
