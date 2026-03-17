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
 *   Platform API for infrastructure DNS-SD provider discovery.
 *
 *   This API is implemented by each platform to detect infrastructure
 *   DNS-SD service providers via IPv6 Router Advertisements.
 *
 *   Platforms should process incoming Router Advertisements and call
 *   InfraDnssdManager::OnRouterAdvertisementReceived() when an RA
 *   contains DNS-SD infrastructure flags.
 *
 *   Platforms may also browse for ad-hoc SRP providers via mDNS
 *   (_dns-sd-srp._tcp) and call
 *   InfraDnssdManager::OnAdHocProviderDiscovered().
 */

#pragma once

#include <lib/core/CHIPError.h>

namespace chip {
namespace Dnssd {

/**
 * Start listening for IPv6 Router Advertisements that carry DNS-SD
 * infrastructure flags.
 *
 * When an RA with the infrastructure or SNAC router flag is received,
 * the platform implementation shall call
 * InfraDnssdManager::Instance().OnRouterAdvertisementReceived().
 *
 * @return CHIP_NO_ERROR on success.
 */
CHIP_ERROR ChipInfraDiscoveryStartRaListener();

/**
 * Stop listening for Router Advertisements.
 */
void ChipInfraDiscoveryStopRaListener();

/**
 * Start browsing for ad-hoc SRP service providers via mDNS.
 *
 * The platform implementation browses for the _dns-sd-srp._tcp service type
 * and calls InfraDnssdManager::Instance().OnAdHocProviderDiscovered()
 * for each discovered provider.
 *
 * @return CHIP_NO_ERROR on success.
 */
CHIP_ERROR ChipInfraDiscoveryStartAdHocBrowse();

/**
 * Stop the ad-hoc SRP provider mDNS browse.
 */
void ChipInfraDiscoveryStopAdHocBrowse();

} // namespace Dnssd
} // namespace chip
