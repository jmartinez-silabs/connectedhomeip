/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
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

/****************************************************************************
 * Copyright 2019, Silicon Laboratories Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the
 *"License"); you may not use this file except in
 *compliance with the License. You may obtain a copy of
 *the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 *writing, software distributed under the License is
 *distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 *OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 *permissions and limitations under the License.
 *****************************************************************************/
#pragma once

#include "FreeRTOS.h"
#include "event_groups.h"
#include "semphr.h"
#include "task.h"
#include "timers.h"

#include "sl_wfx_cmd_api.h"
#include "sl_wfx_constants.h"
/* LwIP includes. */
#include "lwip/apps/httpd.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"

/* Wi-Fi events*/
#define SL_WFX_CONNECT (1 << 1)
#define SL_WFX_DISCONNECT (1 << 2)
#define SL_WFX_START_AP (1 << 3)
#define SL_WFX_STOP_AP (1 << 4)
#define SL_WFX_SCAN_COMPLETE (1 << 5)

typedef enum
{
    WIFI_EVENT,
    IP_EVENT,
} wfx_event_base_t;

typedef enum
{
    IP_EVENT_STA_GOT_IP,
    IP_EVENT_GOT_IP6,
    IP_EVENT_STA_LOST_IP,
} ip_event_id_t;

typedef struct
{
    char ssid[SL_WFX_SSID_SIZE];
    char passkey[64];
    sl_wfx_security_mode_t security;
} wfx_wifi_provision_t;

#ifdef __cplusplus
extern "C" {
#endif

void sl_wfx_host_gpio_init(void);

sl_status_t lwip_set_sta_link_up(void);
sl_status_t lwip_set_sta_link_down(void);
sl_status_t sl_wfx_host_process_event(sl_wfx_generic_message_t * event_payload);
sl_status_t wfx_wifi_start(void);
sl_wfx_state_t wfx_get_wifi_state(void);
void wfx_SetStationNetif(struct netif * newNetif);
struct netif * wfx_GetNetif(sl_wfx_interface_t interface);
sl_wfx_mac_address_t wfx_get_wifi_mac_addr(sl_wfx_interface_t interface);
void wfx_set_wifi_provision(wfx_wifi_provision_t wifiConfig);
bool wfx_get_wifi_provision(wfx_wifi_provision_t * wifiConfig);
void wfx_clear_wifi_provision(void);
sl_status_t wfx_connect_to_provisionned_ap(void);

#ifdef __cplusplus
}
#endif
