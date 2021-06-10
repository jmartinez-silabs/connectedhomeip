/****************************************************************************
 * Copyright 2018, Silicon Laboratories Inc.
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

/* Includes */
#include <string.h>

#include "sl_wifi_config.h"
#include "sl_wfx.h"
#include "sl_wfx_host.h"

/* LwIP includes. */
#include "ethernetif.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"

#include "sl_wfx_host_events.h"

/*****************************************************************************
 * Defines
 ******************************************************************************/
#define STATION_NETIF0 's'
#define STATION_NETIF1 't'

/*****************************************************************************
 * Variables
 ******************************************************************************/

/*****************************************************************************
 * @brief
 *    Initializes the hardware parameters. Called from ethernetif_init().
 *
 * @param[in] netif: the already initialized lwip network interface structure
 *
 * @return
 *    None
 ******************************************************************************/
static void low_level_init(struct netif * netif)
{
    /* set netif MAC hardware address length */
    netif->hwaddr_len = ETH_HWADDR_LEN;

    /* Set netif MAC hardware address */
    sl_wfx_mac_address_t mac_addr = wfx_get_wifi_mac_addr(SL_WFX_STA_INTERFACE);

    netif->hwaddr[0] = mac_addr.octet[0];
    netif->hwaddr[1] = mac_addr.octet[1];
    netif->hwaddr[2] = mac_addr.octet[2];
    netif->hwaddr[3] = mac_addr.octet[3];
    netif->hwaddr[4] = mac_addr.octet[4];
    netif->hwaddr[5] = mac_addr.octet[5];

    /* Set netif maximum transfer unit */
    netif->mtu = 1500;

    /* Accept broadcast address and ARP traffic */
    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP| NETIF_FLAG_IGMP;

    /* Set netif link flag */
    netif->flags |= NETIF_FLAG_LINK_UP|NETIF_FLAG_UP;
}

/*****************************************************************************
 * @brief
 *    This function should does the actual transmission of the packet(s).
 *    The packet is contained in the pbuf that is passed to the function.
 *    This pbuf might be chained.
 *
 * @param[in] netif: the lwip network interface structure
 *
 * @param[in] p: the packet to send
 *
 * @return
 *    ERR_OK if successful
 ******************************************************************************/
static err_t low_level_output(struct netif * netif, struct pbuf * p)
{
    struct pbuf * q;
    sl_wfx_send_frame_req_t * tx_buffer;
    uint8_t * buffer;
    uint32_t framelength;
    uint32_t bufferoffset;
    uint32_t padding;
    sl_status_t result;

    for (q = p, framelength = 0; q != NULL; q = q->next)
    {
        framelength += q->len;
    }
    if (framelength < 60)
    {
        padding = 60 - framelength;
    }
    else
    {
        padding = 0;
    }

    result = sl_wfx_host_allocate_buffer(
        (void **) (&tx_buffer), SL_WFX_TX_FRAME_BUFFER,
        SL_WFX_ROUND_UP(framelength + padding, 64) +
            sizeof(sl_wfx_send_frame_req_t)); // 12 is size of other data in buffer struct, user shouldn't have to care about this?
    if (result != SL_STATUS_OK)
    {
        return ERR_MEM;
    }
    buffer = tx_buffer->body.packet_data;
    /* copy frame from pbufs to driver buffers */
    for (q = p, bufferoffset = 0; q != NULL; q = q->next)
    {
        /* Get bytes in current lwIP buffer */
        memcpy((uint8_t *) ((uint8_t *) buffer + bufferoffset), (uint8_t *) ((uint8_t *) q->payload), q->len);
        bufferoffset += q->len;
    }
    /* No requirement to do this - but we should for security */
    if (padding)
    {
        memset(buffer + bufferoffset, 0, padding);
    }
    /* transmit */
    int i  = 0;
    result = SL_STATUS_FAIL;
    while ((result != SL_STATUS_OK) && (i++ < 10))
    {
        result = sl_wfx_send_ethernet_frame(tx_buffer, framelength + padding, SL_WFX_STA_INTERFACE, 0);
    }
    sl_wfx_host_free_buffer(tx_buffer, SL_WFX_TX_FRAME_BUFFER);

    if (result != SL_STATUS_OK)
    {
        printf("Failed to send ethernet frame\r\n");
        return ERR_IF;
    }
    return ERR_OK;
}

/*****************************************************************************
 * @brief
 *    This function transfers the receive packets from the wf200 to lwip.
 *
 * @param[in] netif: the lwip network interface structure
 *
 * @param[in] rx_buffer: the ethernet frame received by the wf200
 *
 * @return
 *    LwIP pbuf filled with received packet, or NULL on error
 ******************************************************************************/
static struct pbuf * low_level_input(struct netif * netif, sl_wfx_received_ind_t * rx_buffer)
{
    struct pbuf *p, *q;
    uint16_t len;
    uint8_t * buffer;
    uint32_t bufferoffset;

    len = rx_buffer->body.frame_length;
    if (len <= 0)
        return (struct pbuf *) 0;
    buffer = (uint8_t *) &(rx_buffer->body.frame[rx_buffer->body.frame_padding]);
    /* We allocate a pbuf chain of pbufs from the Lwip buffer pool
     * and copy the data to the pbuf chain
     */
    if ((p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL)) != (struct pbuf *) 0)
    {
        for (q = p, bufferoffset = 0; q != NULL; q = q->next)
        {
            memcpy((uint8_t *) q->payload, (uint8_t *) buffer + bufferoffset, q->len);
            bufferoffset += q->len;
            // ASSERT(bufferoffset <= len);
        }
    }

    return p;
}

/*****************************************************************************
 * @brief
 *    This function implements the wf200 received frame callback.
 *    Called from the context of the bus_task (not ISR)
 *
 * @param[in] rx_buffer: the ethernet frame received by the wf200
 *
 * @return
 *    None
 ******************************************************************************/
void sl_wfx_host_received_frame_callback(sl_wfx_received_ind_t * rx_buffer)
{
    struct pbuf * p;
    struct netif * netif;

    /* Check packet interface to send to AP or STA interface */
    if ((rx_buffer->header.info & SL_WFX_MSG_INFO_INTERFACE_MASK) == (SL_WFX_STA_INTERFACE << SL_WFX_MSG_INFO_INTERFACE_OFFSET))
    {
        /* Send to station interface */
        netif = wfx_GetNetif(SL_WFX_STA_INTERFACE);
    }

    if (netif != NULL)
    {
        p = low_level_input(netif, rx_buffer);
        if (p != NULL)
        {
            if (netif->input(p, netif) != ERR_OK)
            {
                pbuf_free(p);
            }
        }
    }
}

/*****************************************************************************
 * @brief
 *    called at the beginning of the program to set up the network interface.
 *
 * @param[in] netif: the lwip network interface structure
 *
 * @return
 *    ERR_OK if successful
 ******************************************************************************/
err_t sta_ethernetif_init(struct netif * netif)
{
    LWIP_ASSERT("netif != NULL", (netif != NULL));

    /* Set the netif name to identify the interface */
    netif->name[0] = STATION_NETIF0;
    netif->name[1] = STATION_NETIF1;

    netif->output     = etharp_output;
    netif->output_ip6 = ethip6_output;
    netif->linkoutput = low_level_output;

    /* initialize the hardware */
    low_level_init(netif);
    wfx_SetStationNetif(netif);

    return ERR_OK;
}
