/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
 *    Copyright (c) 2019 Nest Labs, Inc.
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
/* this file behaves like a config.h, comes first */
#include <platform/internal/CHIPDeviceLayerInternal.h>

#include <platform/ConnectivityManager.h>
#include <platform/internal/BLEManager.h>
#include <support/CodeUtils.h>
#include <support/logging/CHIPLogging.h>

#include <lwip/dns.h>
#include <lwip/ip_addr.h>
#include <lwip/nd6.h>
#include <lwip/netif.h>

#if CHIP_DEVICE_CONFIG_ENABLE_CHIPOBLE
#include <platform/internal/GenericConnectivityManagerImpl_BLE.cpp>
#endif

#if CHIP_DEVICE_CONFIG_ENABLE_THREAD
#include <platform/internal/GenericConnectivityManagerImpl_Thread.cpp>
#endif

#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_STATION
#include "sl_wfx.h"
#include "sl_wfx_host_events.h"
#include <platform/EFR32/WFXUtils.h>
#include <platform/internal/GenericConnectivityManagerImpl_WiFi.cpp>
#endif

using namespace ::chip;
using namespace ::chip::Inet;
using namespace ::chip::System;
using namespace ::chip::TLV;
using namespace ::chip::DeviceLayer::Internal;

namespace chip {
namespace DeviceLayer {

ConnectivityManagerImpl ConnectivityManagerImpl::sInstance;

CHIP_ERROR ConnectivityManagerImpl::_Init()
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    // Initialize the generic base classes that require it.
#if CHIP_DEVICE_CONFIG_ENABLE_THREAD
    GenericConnectivityManagerImpl_Thread<ConnectivityManagerImpl>::_Init();
#endif
#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_STATION
    // Queue work items to bootstrap the AP and station state machines once the Chip event loop is running.
    mLastStationConnectFailTime     = 0;
    mWiFiStationMode                = kWiFiStationMode_Disabled;
    mWiFiStationState               = kWiFiStationState_NotConnected;
    mWiFiStationReconnectIntervalMS = CHIP_DEVICE_CONFIG_WIFI_STATION_RECONNECT_INTERVAL;
    mFlags                          = 0;

    // TODO Initialize the Chip Addressing and Routing Module.

    // Ensure that station mode is enabled.
    err = Internal::WFXUtils::EnableStationMode();
    SuccessOrExit(err);

    err = SystemLayer.ScheduleWork(DriveStationState, NULL);
    SuccessOrExit(err);
#endif
    SuccessOrExit(err);

exit:
    return err;
}

void ConnectivityManagerImpl::_OnPlatformEvent(const ChipDeviceEvent * event)
{
    // Forward the event to the generic base classes as needed.
#if CHIP_DEVICE_CONFIG_ENABLE_THREAD
    GenericConnectivityManagerImpl_Thread<ConnectivityManagerImpl>::_OnPlatformEvent(event);
#endif

#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_STATION
    // Handle Wfx wifi events...
    if (event->Type == DeviceEventType::kWFXSystemEvent)
    {
        if (event->Platform.WFXSystemEvent.eventBase == WIFI_EVENT)
        {
            switch (event->Platform.WFXSystemEvent.data.genericMsgEvent.header.id)
            {
            case SL_WFX_STARTUP_IND_ID:
                ChipLogProgress(DeviceLayer, "WIFI_EVENT_STA_START");
                DriveStationState();
                break;
            case SL_WFX_CONNECT_IND_ID:
                ChipLogProgress(DeviceLayer, "WIFI_EVENT_STA_CONNECTED");
                if (mWiFiStationState == kWiFiStationState_Connecting)
                {
                    if (event->Platform.WFXSystemEvent.data.connectEvent.body.status == WFM_STATUS_SUCCESS)
                    {
                        ChangeWiFiStationState(kWiFiStationState_Connecting_Succeeded);
                    }
                    else
                    {
                        ChangeWiFiStationState(kWiFiStationState_Connecting_Failed);
                    }
                }
                DriveStationState();
                break;
            case SL_WFX_DISCONNECT_IND_ID:
                ChipLogProgress(DeviceLayer, "WIFI_EVENT_STA_DISCONNECTED");
                if (mWiFiStationState == kWiFiStationState_Connecting)
                {
                    ChangeWiFiStationState(kWiFiStationState_Connecting_Failed);
                }
                DriveStationState();
                break;
            default:
                break;
            }
        }
        else if (event->Platform.WFXSystemEvent.eventBase == IP_EVENT)
        {
            switch (event->Platform.WFXSystemEvent.data.genericMsgEvent.header.id)
            {
            case IP_EVENT_STA_GOT_IP:
                ChipLogProgress(DeviceLayer, "IP_EVENT_STA_GOT_IP");
                UpdateInternetConnectivityState();
                break;
            case IP_EVENT_STA_LOST_IP:
                ChipLogProgress(DeviceLayer, "IP_EVENT_STA_LOST_IP");
                UpdateInternetConnectivityState();
                break;
            case IP_EVENT_GOT_IP6:
                ChipLogProgress(DeviceLayer, "IP_EVENT_GOT_IP6");
                UpdateInternetConnectivityState();
                break;
            default:
                break;
            }
        }
    }
#endif
}

#if CHIP_DEVICE_CONFIG_ENABLE_WIFI_STATION
ConnectivityManager::WiFiStationMode ConnectivityManagerImpl::_GetWiFiStationMode(void)
{
    if (mWiFiStationMode != kWiFiStationMode_ApplicationControlled)
    {
        wifi_mode_t curWiFiMode = WFXUtils::GetWifiMode();
        if ((curWiFiMode == WIFI_MODE_STA) || (curWiFiMode == WIFI_MODE_APSTA))
        {
            mWiFiStationMode = kWiFiStationMode_Enabled;
        }
        else
        {
            mWiFiStationMode = kWiFiStationMode_Disabled;
        }
    }
    return mWiFiStationMode;
}

bool ConnectivityManagerImpl::_IsWiFiStationEnabled(void)
{
    return GetWiFiStationMode() == kWiFiStationMode_Enabled;
}

CHIP_ERROR ConnectivityManagerImpl::_SetWiFiStationMode(WiFiStationMode val)
{
    SystemLayer.ScheduleWork(DriveStationState, NULL);

    if (mWiFiStationMode != val)
    {
        ChipLogProgress(DeviceLayer, "WiFi station mode change: %s -> %s", WiFiStationModeToStr(mWiFiStationMode),
                        WiFiStationModeToStr(val));
    }

    mWiFiStationMode = val;

    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR ConnectivityManagerImpl::_SetWiFiStationReconnectIntervalMS(uint32_t val)
{
    mWiFiStationReconnectIntervalMS = val;
    return 0;
}

bool ConnectivityManagerImpl::_IsWiFiStationProvisioned(void)
{
    return Internal::WFXUtils::IsStationProvisioned();
}

void ConnectivityManagerImpl::_ClearWiFiStationProvision(void)
{
    if (mWiFiStationMode != kWiFiStationMode_ApplicationControlled)
    {
        Internal::WFXUtils::ClearWiFiStationProvision();

        SystemLayer.ScheduleWork(DriveStationState, NULL);
    }
}

CHIP_ERROR ConnectivityManagerImpl::_GetAndLogWifiStatsCounters(void)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}

void ConnectivityManagerImpl::_OnWiFiScanDone()
{
    // CHIP_ERROR_NOT_IMPLEMENTED
}

void ConnectivityManagerImpl::_OnWiFiStationProvisionChange()
{
    // Schedule a call to the DriveStationState method to adjust the station state as needed.
    ChipLogProgress(DeviceLayer, "_ON WIFI PROVISION CHANGE");
    SystemLayer.ScheduleWork(DriveStationState, NULL);
}

// == == == == == == == == == == ConnectivityManager Private Methods == == == == == == == == == ==

void ConnectivityManagerImpl::DriveStationState()
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    bool stationConnected;

    // Refresh the current station mode.
    GetWiFiStationMode();

    // If the station interface is NOT under application control...
    if (mWiFiStationMode != kWiFiStationMode_ApplicationControlled)
    {
        // Ensure that the WFX is started.
        err = Internal::WFXUtils::StartWiFiLayer();
        SuccessOrExit(err);

        // Ensure that station mode is enabled in the ESP WiFi layer.
        err = Internal::WFXUtils::EnableStationMode();
        SuccessOrExit(err);
    }

    // Determine if the WFX WiFi station interface is currently connected.
    err = Internal::WFXUtils::IsStationConnected(stationConnected);
    SuccessOrExit(err);

    // If the station interface is currently connected ...
    if (stationConnected)
    {
        // Advance the station state to Connected if it was previously NotConnected or
        // a previously initiated connect attempt succeeded.
        if (mWiFiStationState == kWiFiStationState_NotConnected || mWiFiStationState == kWiFiStationState_Connecting_Succeeded)
        {
            ChangeWiFiStationState(kWiFiStationState_Connected);
            ChipLogProgress(DeviceLayer, "WiFi station interface connected");
            mLastStationConnectFailTime = 0;
            OnStationConnected();
        }

        // If the WiFi station interface is no longer enabled, or no longer provisioned,
        // disconnect the station from the AP, unless the WiFi station mode is currently
        // under application control.
        if (mWiFiStationMode != kWiFiStationMode_ApplicationControlled &&
            (mWiFiStationMode != kWiFiStationMode_Enabled || !IsWiFiStationProvisioned()))
        {
            ChipLogProgress(DeviceLayer, "Disconnecting WiFi station interface");
            err = sl_wfx_send_disconnect_command();
            if (err != SL_STATUS_OK)
            {
                ChipLogError(DeviceLayer, "wfx_wifi_disconnect() failed: %s", chip::ErrorStr(err));
            }
            SuccessOrExit(err);

            ChangeWiFiStationState(kWiFiStationState_Disconnecting);
        }
    }
    // Otherwise the station interface is NOT connected to an AP, so...
    else
    {
        uint64_t now = System::Layer::GetClock_MonotonicMS();

        // Advance the station state to NotConnected if it was previously Connected or Disconnecting,
        // or if a previous initiated connect attempt failed.
        if (mWiFiStationState == kWiFiStationState_Connected || mWiFiStationState == kWiFiStationState_Disconnecting ||
            mWiFiStationState == kWiFiStationState_Connecting_Failed)
        {
            WiFiStationState prevState = mWiFiStationState;
            ChangeWiFiStationState(kWiFiStationState_NotConnected);
            if (prevState != kWiFiStationState_Connecting_Failed)
            {
                ChipLogProgress(DeviceLayer, "WiFi station interface disconnected");
                mLastStationConnectFailTime = 0;
                OnStationDisconnected();
            }
            else
            {
                mLastStationConnectFailTime = now;
            }
        }

        // If the WiFi station interface is now enabled and provisioned (and by implication,
        // not presently under application control), AND the system is not in the process of
        // scanning, then...
        if (mWiFiStationMode == kWiFiStationMode_Enabled && IsWiFiStationProvisioned())
        {
            // Initiate a connection to the AP if we haven't done so before, or if enough
            // time has passed since the last attempt.
            if (mLastStationConnectFailTime == 0 || now >= mLastStationConnectFailTime + mWiFiStationReconnectIntervalMS)
            {
                if (mWiFiStationState != kWiFiStationState_Connecting)
                {
                    ChipLogProgress(DeviceLayer, "Attempting to connect WiFi station interface");
                    err = wfx_connect_to_provisionned_ap();
                    if (err != SL_STATUS_OK)
                    {
                        ChipLogError(DeviceLayer, "wfx_connect_to_provisionned_ap() failed: %s", chip::ErrorStr(err));
                    }
                    SuccessOrExit(err);

                    ChangeWiFiStationState(kWiFiStationState_Connecting);
                }
            }

            // Otherwise arrange another connection attempt at a suitable point in the future.
            else
            {
                uint32_t timeToNextConnect = (uint32_t)((mLastStationConnectFailTime + mWiFiStationReconnectIntervalMS) - now);

                ChipLogProgress(DeviceLayer, "Next WiFi station reconnect in %" PRIu32 " ms", timeToNextConnect);

                err = SystemLayer.StartTimer(timeToNextConnect, DriveStationState, NULL);
                SuccessOrExit(err);
            }
        }
    }

exit:

    ChipLogProgress(DeviceLayer, "Done driving station state, nothing else to do...");
    // Kick-off any pending network scan that might have been deferred due to the activity
    // of the WiFi station.
}

void ConnectivityManagerImpl::OnStationConnected()
{
    // TODO Assign ipv6 addr to wfx station
    // CHIP_ERROR err;
    // Assign an IPv6 link local address to the station interface.
    // err = esp_netif_create_ip6_linklocal(esp_netif_get_handle_from_ifkey("WIFI_STA_DEF"));
    // if (err != ESP_OK)
    // {
    //     ChipLogError(DeviceLayer, "esp_netif_create_ip6_linklocal() failed for WIFI_STA_DEF interface: %s", chip::ErrorStr(err));
    // }

    // TODO Invoke WARM to perform actions that occur when the WiFi station interface comes up.

    // Alert other components of the new state.
    ChipDeviceEvent event;
    event.Type                          = DeviceEventType::kWiFiConnectivityChange;
    event.WiFiConnectivityChange.Result = kConnectivity_Established;
    PlatformMgr().PostEvent(&event);

    UpdateInternetConnectivityState();
}

void ConnectivityManagerImpl::OnStationDisconnected()
{
    // TODO Invoke WARM to perform actions that occur when the WiFi station interface goes down.

    // Alert other components of the new state.
    ChipDeviceEvent event;
    event.Type                          = DeviceEventType::kWiFiConnectivityChange;
    event.WiFiConnectivityChange.Result = kConnectivity_Lost;
    PlatformMgr().PostEvent(&event);

    UpdateInternetConnectivityState();
}

void ConnectivityManagerImpl::ChangeWiFiStationState(WiFiStationState newState)
{
    if (mWiFiStationState != newState)
    {
        ChipLogProgress(DeviceLayer, "WiFi station state change: %s -> %s", WiFiStationStateToStr(mWiFiStationState),
                        WiFiStationStateToStr(newState));
        mWiFiStationState = newState;
    }
}

void ConnectivityManagerImpl::DriveStationState(::chip::System::Layer * aLayer, void * aAppState, ::chip::System::Error aError)
{
    sInstance.DriveStationState();
}

void ConnectivityManagerImpl::UpdateInternetConnectivityState(void)
{
    bool haveIPv4Conn = false;
    bool haveIPv6Conn = false;
    bool hadIPv4Conn  = GetFlag(mFlags, kFlag_HaveIPv4InternetConnectivity);
    bool hadIPv6Conn  = GetFlag(mFlags, kFlag_HaveIPv6InternetConnectivity);
    IPAddress addr;

    // If the WiFi station is currently in the connected state...
    if (mWiFiStationState == kWiFiStationState_Connected)
    {
        // Get the LwIP netif for the WiFi station interface.
        struct netif * netif = Internal::WFXUtils::GetStationNetif();

        // If the WiFi station interface is up...
        if (netif != NULL && netif_is_up(netif) && netif_is_link_up(netif))
        {
            // // Check if a DNS server is currently configured.  If so...
            // TODO
            // ip_addr_t dnsServerAddr = *dns_getserver(0);
            // if (!ip_addr_isany_val(dnsServerAddr))
            if (1)
            {
                // If the station interface has been assigned an IPv4 address, and has
                // an IPv4 gateway, then presume that the device has IPv4 Internet
                // connectivity.
                if (!ip4_addr_isany_val(*netif_ip4_addr(netif)) && !ip4_addr_isany_val(*netif_ip4_gw(netif)))
                {
                    haveIPv4Conn = true;
                    char addrStr[INET_ADDRSTRLEN];
                    // TODO: change the code to using IPv6 address
                    sprintf(addrStr, "%d.%d.%d.%d", (int) (netif->ip_addr.u_addr.ip4.addr & 0xff),
                            (int) ((netif->ip_addr.u_addr.ip4.addr >> 8) & 0xff),
                            (int) ((netif->ip_addr.u_addr.ip4.addr >> 16) & 0xff),
                            (int) ((netif->ip_addr.u_addr.ip4.addr >> 24) & 0xff));
                    IPAddress::FromString(addrStr, addr);
                }

                // TODO
                // Search among the IPv6 addresses assigned to the interface for a Global Unicast
                // address (2000::/3) that is in the valid state.  If such an address is found...
                // for (uint8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
                // {
                //     if (ip6_addr_isglobal(netif_ip6_addr(netif, i)) && ip6_addr_isvalid(netif_ip6_addr_state(netif, i)))
                //     {
                //         // Determine if there is a default IPv6 router that is currently reachable
                //         // via the station interface.  If so, presume for now that the device has
                //         // IPv6 connectivity.
                //         struct netif * found_if = nd6_find_route(IP6_ADDR_ANY6);
                //         if (found_if && netif->num == found_if->num)
                //         {
                //             haveIPv6Conn = true;
                //         }
                //     }
                // }
            }
        }
    }

    // If the internet connectivity state has changed...
    if (haveIPv4Conn != hadIPv4Conn || haveIPv6Conn != hadIPv6Conn)
    {
        // Update the current state.
        SetFlag(mFlags, kFlag_HaveIPv4InternetConnectivity, haveIPv4Conn);
        SetFlag(mFlags, kFlag_HaveIPv6InternetConnectivity, haveIPv6Conn);

        // Alert other components of the state change.
        ChipDeviceEvent event;
        event.Type                            = DeviceEventType::kInternetConnectivityChange;
        event.InternetConnectivityChange.IPv4 = GetConnectivityChange(hadIPv4Conn, haveIPv4Conn);
        event.InternetConnectivityChange.IPv6 = GetConnectivityChange(hadIPv6Conn, haveIPv6Conn);
        addr.ToString(event.InternetConnectivityChange.address, sizeof(event.InternetConnectivityChange.address));
        PlatformMgr().PostEvent(&event);

        if (haveIPv4Conn != hadIPv4Conn)
        {
            ChipLogProgress(DeviceLayer, "%s Internet connectivity %s", "IPv4", (haveIPv4Conn) ? "ESTABLISHED" : "LOST");
        }

        if (haveIPv6Conn != hadIPv6Conn)
        {
            ChipLogProgress(DeviceLayer, "%s Internet connectivity %s", "IPv6", (haveIPv6Conn) ? "ESTABLISHED" : "LOST");
        }
    }
}

#endif
} // namespace DeviceLayer
} // namespace chip
