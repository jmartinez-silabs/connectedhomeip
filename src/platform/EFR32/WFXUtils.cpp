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

/**
 *    @file
 *          General utility methods for the ESP32 platform.
 */
/* this file behaves like a config.h, comes first */
#include <platform/internal/CHIPDeviceLayerInternal.h>

#include <platform/EFR32/EFR32Config.h>
#include <platform/EFR32/WFXUtils.h>
#include <support/CodeUtils.h>
#include <support/ErrorStr.h>
#include <support/logging/CHIPLogging.h>

#include "sl_wfx.h"
#include "sl_wfx_host_events.h"

using namespace ::chip::DeviceLayer::Internal;
using chip::DeviceLayer::Internal::DeviceNetworkInfo;

bool WFXUtils::IsStationProvisioned(void)
{
    wfx_wifi_provision_t stationConfig;
    return (wfx_get_wifi_provision(&stationConfig) == true && stationConfig.ssid[0] != 0);
}

CHIP_ERROR WFXUtils::IsStationConnected(bool & connected)
{
    connected = ((wfx_get_wifi_state() & SL_WFX_STA_INTERFACE_CONNECTED) == SL_WFX_STA_INTERFACE_CONNECTED);
    return CHIP_NO_ERROR;
}
static void
do_set_wifi_sta_vars(const char *ssid, const char *psk)
{
    wfx_wifi_provision_t wifiConfig;

    memset(&wifiConfig, 0, sizeof(wifiConfig));
    strncpy (wifiConfig.ssid, ssid, sizeof (wifiConfig.ssid) -1);
    strncpy (wifiConfig.passkey, psk, sizeof (wifiConfig.passkey) -1);
    wifiConfig.security = WFM_SECURITY_MODE_WPA2_PSK;

    // Configure the WFX WiFi interface.
    wfx_set_wifi_provision (&wifiConfig);
    ChipLogProgress(DeviceLayer, "DO WFXUTILS WiFi STA set (SSID: %s)", ssid);
}

CHIP_ERROR WFXUtils::StartWiFiLayer(void)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    char ssid [kMaxWiFiSSIDLength], psk [kMaxWiFiKeyLength + 1];
    size_t slen, plen;

    ChipLogProgress(DeviceLayer, "WFXUtils:Start WiFi");
    if (!((wfx_get_wifi_state() & SL_WFX_STARTED) == SL_WFX_STARTED))
    {
        err = wfx_wifi_start();
        if (err != SL_STATUS_OK)
        {
            ChipLogError(DeviceLayer, "WFX_wifi_start: FAIL: %s", chip::ErrorStr(err));
        }
#if 1
        /*
         * Get our Provision Keys and set it.
         */
        if (((err = EFR32Config::ReadConfigValueStr (EFR32Config::kConfigKey_OperationalWiFiSSID, &ssid [0], sizeof (ssid)-1, slen)) != CHIP_NO_ERROR) ||
            ((err = EFR32Config::ReadConfigValueStr (EFR32Config::kConfigKey_OperationalWiFiPSK, &psk [0], sizeof (psk) -1, plen)) != CHIP_NO_ERROR))
            {
                ChipLogError(DeviceLayer, "WIFI: NO SSID found in NVM3 %s", chip::ErrorStr(err));
            } else {
            /*
             * Got the SSID/PSK from before - Set it.
             */
            ChipLogProgress(DeviceLayer, "WFX: Found SSID=%s", ssid);
            do_set_wifi_sta_vars (ssid, psk);
        }
#endif
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR WFXUtils::EnableStationMode(void)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    // wifi_mode_t curWiFiMode;

    // // Get the current ESP WiFI mode.
    // err = esp_wifi_get_mode(&curWiFiMode);
    // if (err != ESP_OK)
    // {
    //     ChipLogError(DeviceLayer, "esp_wifi_get_mode() failed: %s", chip::ErrorStr(err));
    // }
    // SuccessOrExit(err);

    // // If station mode is not already enabled (implying the current mode is WIFI_MODE_AP), change
    // // the mode to WIFI_MODE_APSTA.
    // if (curWiFiMode == WIFI_MODE_AP)
    // {
    //     ChipLogProgress(DeviceLayer, "Changing ESP WiFi mode: %s -> %s", WiFiModeToStr(WIFI_MODE_AP),
    //                     WiFiModeToStr(WIFI_MODE_APSTA));

    //     err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    //     if (err != ESP_OK)
    //     {
    //         ChipLogError(DeviceLayer, "esp_wifi_set_mode() failed: %s", chip::ErrorStr(err));
    //     }
    //     SuccessOrExit(err);
    // }

    // exit:
    return err;
}

int WFXUtils::OrderScanResultsByRSSI(const int32_t rssi1, const int32_t rssi2)
{
    if (rssi1 > rssi2)
    {
        return -1;
    }
    if (rssi1 < rssi2)
    {
        return 1;
    }
    return 0;
}

const char * WFXUtils::WiFiModeToStr(wifi_mode_t wifiMode)
{
    switch (wifiMode)
    {
    case WIFI_MODE_NULL:
        return "NULL";
    case WIFI_MODE_STA:
        return "STA";
    case WIFI_MODE_AP:
        return "AP";
    case WIFI_MODE_APSTA:
        return "STA+AP";
    default:
        return "(unknown)";
    }
}

struct netif * WFXUtils::GetStationNetif(void)
{
    return wfx_GetNetif(SL_WFX_STA_INTERFACE);
}

bool WFXUtils::IsInterfaceUp(sl_wfx_interface_t interface)
{
    struct netif * netif = wfx_GetNetif(interface);
    return ((netif != NULL) && netif_is_up(netif));
}

CHIP_ERROR WFXUtils::GetWiFiStationProvision(Internal::DeviceNetworkInfo & netInfo, bool includeCredentials)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    wfx_wifi_provision_t stationConfig;

    err = (wfx_get_wifi_provision(&stationConfig) ? CHIP_NO_ERROR : CHIP_ERROR_INVALID_ADDRESS);
    SuccessOrExit(err);

    VerifyOrExit(stationConfig.ssid[0] != 0, err = CHIP_ERROR_INCORRECT_STATE);

    netInfo.NetworkId              = kWiFiStationNetworkId;
    netInfo.FieldPresent.NetworkId = true;
    memcpy(netInfo.WiFiSSID, stationConfig.ssid,
           min(strlen(reinterpret_cast<char *>(stationConfig.ssid)) + 1, sizeof(netInfo.WiFiSSID)));

    // Enforce that netInfo wifiSSID is null terminated
    netInfo.WiFiSSID[kMaxWiFiSSIDLength] = '\0';

    if (includeCredentials)
    {
        static_assert(sizeof(netInfo.WiFiKey) < 255, "Our min might not fit in netInfo.WiFiKeyLen");
        netInfo.WiFiKeyLen = static_cast<uint8_t>(min(strlen((char *) stationConfig.passkey), sizeof(netInfo.WiFiKey)));
        memcpy(netInfo.WiFiKey, stationConfig.passkey, netInfo.WiFiKeyLen);
    }

exit:
    return err;
}

CHIP_ERROR WFXUtils::SetWiFiStationProvision(const Internal::DeviceNetworkInfo & netInfo)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    char psk [kMaxWiFiKeyLength + 1];

    // Ensure that WFX station mode is enabled.
    err = WFXUtils::EnableStationMode();
    SuccessOrExit(err);

    if (netInfo.WiFiKeyLen >= (sizeof (psk) -1)) {
        return CHIP_ERROR_NO_MEMORY;
    }
    memcpy (&psk [0], netInfo.WiFiKey, netInfo.WiFiKeyLen);
    psk [netInfo.WiFiKeyLen] = 0;
    do_set_wifi_sta_vars (&netInfo.WiFiSSID [0], psk);
#if 0
    /*
     * We are required to remember this
     */
    (void)EFR32Config::WriteConfigValueStr (EFR32Config::kConfigKey_OperationalWiFiSSID, (char *)&netInfo.WiFiSSID[0]);
    (void)EFR32Config::WriteConfigValueStr (EFR32Config::kConfigKey_OperationalWiFiPSK, psk);
#endif
    ChipLogProgress(DeviceLayer, "$$$WFXUtils:WiFi STA provision (SSID: %s)", netInfo.WiFiSSID);
exit:
    return err;
}

CHIP_ERROR WFXUtils::ClearWiFiStationProvision(void)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    wfx_clear_wifi_provision();
    (void)EFR32Config::ClearConfigValue (EFR32Config::kConfigKey_OperationalWiFiSSID);
    (void)EFR32Config::ClearConfigValue (EFR32Config::kConfigKey_OperationalWiFiPSK);
    return err;
}

wifi_mode_t WFXUtils::GetWifiMode(void)
{
    wifi_mode_t wifiMode    = WIFI_MODE_NULL;
    sl_wfx_state_t wfxState = wfx_get_wifi_state();
    if (wfxState & SL_WFX_STARTED)
    {
        // In our use case, if the WFX is stated, it is in Station mode .
        // Check if AP interface is up to know if Access point mode is active too.
        wifiMode = (wfxState & SL_WFX_AP_INTERFACE_UP) ? WIFI_MODE_APSTA : WIFI_MODE_STA;
    }

    return wifiMode;
}
