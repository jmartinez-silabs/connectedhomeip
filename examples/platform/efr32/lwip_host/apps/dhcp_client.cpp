/*****************************************************************************
 * @file
 * @brief LwIP DHCP client implementation
 *******************************************************************************
 * # License
 * <b>Copyright 2019 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/
#include "dhcp_client.h"
#include "demo_config.h"
#include "lwip/dhcp.h"

#include "FreeRTOS.h"
#include "event_groups.h"
#include "task.h"

#include "AppConfig.h"
#include "sl_wfx_task.h"

#include <platform/CHIPDeviceLayer.h>

using namespace ::chip;
using namespace ::chip::DeviceLayer;

// DHCP client states
#define DHCP_OFF (uint8_t) 0
#define DHCP_START (uint8_t) 1
#define DHCP_WAIT_ADDRESS (uint8_t) 2
#define DHCP_ADDRESS_ASSIGNED (uint8_t) 3
#define DHCP_TIMEOUT (uint8_t) 4
#define DHCP_LINK_DOWN (uint8_t) 5

#define MAX_DHCP_TRIES 4

/* Station IP address */
uint8_t sta_ip_addr0      = STA_IP_ADDR0_DEFAULT;
uint8_t sta_ip_addr1      = STA_IP_ADDR1_DEFAULT;
uint8_t sta_ip_addr2      = STA_IP_ADDR2_DEFAULT;
uint8_t sta_ip_addr3      = STA_IP_ADDR3_DEFAULT;
uint8_t sta_netmask_addr0 = STA_NETMASK_ADDR0_DEFAULT;
uint8_t sta_netmask_addr1 = STA_NETMASK_ADDR1_DEFAULT;
uint8_t sta_netmask_addr2 = STA_NETMASK_ADDR2_DEFAULT;
uint8_t sta_netmask_addr3 = STA_NETMASK_ADDR3_DEFAULT;
uint8_t sta_gw_addr0      = STA_GW_ADDR0_DEFAULT;
uint8_t sta_gw_addr1      = STA_GW_ADDR1_DEFAULT;
uint8_t sta_gw_addr2      = STA_GW_ADDR2_DEFAULT;
uint8_t sta_gw_addr3      = STA_GW_ADDR3_DEFAULT;

/// Current DHCP state machine state.
static volatile uint8_t dhcp_state = DHCP_OFF;
TaskHandle_t DHCPTaskHandle;

/*****************************************************************************
 * Notify DHCP client task about the wifi status
 *
 * @param link_up link status
 ******************************************************************************/
void dhcpclient_set_link_state(int link_up)
{
    if (link_up)
    {
        dhcp_state = DHCP_START;
    }
    else
    {
        /* Update DHCP state machine */
        dhcp_state = DHCP_LINK_DOWN;
    }
}

/*****************************************************************************
 * DHCP client task.
 *
 * @param arg Network interface
 ******************************************************************************/
static void dhcpclient_task(void * argument)
{
    struct netif * netif = (struct netif *) argument;
    ip_addr_t ipaddr;
    ip_addr_t netmask;
    ip_addr_t gw;
    struct dhcp * dhcp;

    for (;;)
    {
        switch (dhcp_state)
        {
        case DHCP_START: {
            ip_addr_set_zero_ip4(&netif->ip_addr);
            ip_addr_set_zero_ip4(&netif->netmask);
            ip_addr_set_zero_ip4(&netif->gw);
            dhcp_start(netif);
            dhcp_state = DHCP_WAIT_ADDRESS;
        }
        break;

        case DHCP_WAIT_ADDRESS: {
            if (dhcp_supplied_address(netif))
            {
                dhcp_state = DHCP_ADDRESS_ASSIGNED;

                EFR32_LOG("WFX Station IP: %d.%d.%d.%d", (netif->ip_addr.u_addr.ip4.addr & 0xff),
                          ((netif->ip_addr.u_addr.ip4.addr >> 8) & 0xff), ((netif->ip_addr.u_addr.ip4.addr >> 16) & 0xff),
                          ((netif->ip_addr.u_addr.ip4.addr >> 24) & 0xff));

                sl_wfx_generic_message_t eventData;
                memset(&eventData, 0, sizeof(eventData));
                eventData.header.id     = IP_EVENT_STA_GOT_IP;
                eventData.header.length = sizeof(eventData.header);
                PlatformMgrImpl().HandleWFXSystemEvent(IP_EVENT, &eventData);
            }
            else
            {
                dhcp = (struct dhcp *) netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP);

                /* DHCP timeout */
                if (dhcp->tries > MAX_DHCP_TRIES)
                {
                    dhcp_state = DHCP_TIMEOUT;

                    /* Stop DHCP */
                    dhcp_stop(netif);

                    /* Static address used */
                    IP_ADDR4(&ipaddr, sta_ip_addr0, sta_ip_addr1, sta_ip_addr2, sta_ip_addr3);
                    IP_ADDR4(&netmask, sta_netmask_addr0, sta_netmask_addr1, sta_netmask_addr2, sta_netmask_addr3);
                    IP_ADDR4(&gw, sta_gw_addr0, sta_gw_addr1, sta_gw_addr2, sta_gw_addr3);
                    netif_set_addr(netif, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gw));
                }
            }
        }
        break;
        case DHCP_LINK_DOWN: {
            /* Stop DHCP */
            dhcp_stop(netif);
            dhcp_state = DHCP_OFF;
            sl_wfx_generic_message_t eventData;
            memset(&eventData, 0, sizeof(eventData));
            eventData.header.id     = IP_EVENT_STA_LOST_IP;
            eventData.header.length = sizeof(eventData.header);
            PlatformMgrImpl().HandleWFXSystemEvent(IP_EVENT, &eventData);
        }
        break;
        default:
            break;
        }

        /* wait 250 ms */
        vTaskDelay(portMS_TO_TICKS(250));
    }
}

/*****************************************************************************
 * Start DHCP client task.
 ******************************************************************************/
void dhcpclient_start(void)
{
    if (xTaskCreate(dhcpclient_task, "DHCPTask", 256, wfx_GetNetif(SL_WFX_STA_INTERFACE), 1, &DHCPTaskHandle) != pdPASS)
    {
        EFR32_LOG("Failed to create WFX secureLinkTask");
    }
}
