/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
 *    Copyright (c) 2018 Nest Labs, Inc.
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

#include "platform/internal/DeviceNetworkInfo.h"
#include <platform/internal/CHIPDeviceLayerInternal.h>

namespace chip {
namespace DeviceLayer {
namespace Internal {

typedef enum
{
    WIFI_MODE_NULL = 0,
    WIFI_MODE_STA,
    WIFI_MODE_AP,
    WIFI_MODE_APSTA,
    WIFI_MODE_MAX,
} wifi_mode_t;

class WFXUtils
{
public:
    static bool IsStationProvisioned(void);
    static CHIP_ERROR IsStationConnected(bool & connected);
    static CHIP_ERROR StartWiFiLayer(void);
    static CHIP_ERROR EnableStationMode(void);
    static int OrderScanResultsByRSSI(const int32_t rssi1, const int32_t rssi2);
    static const char * WiFiModeToStr(wifi_mode_t wifiMode);
    static struct netif * GetStationNetif(void);
    static bool IsInterfaceUp(sl_wfx_interface_t interface);

    static CHIP_ERROR GetWiFiStationProvision(Internal::DeviceNetworkInfo & netInfo, bool includeCredentials);
    static CHIP_ERROR SetWiFiStationProvision(const Internal::DeviceNetworkInfo & netInfo);
    static CHIP_ERROR ClearWiFiStationProvision(void);
    static wifi_mode_t GetWifiMode(void);
};

} // namespace Internal
} // namespace DeviceLayer
} // namespace chip
