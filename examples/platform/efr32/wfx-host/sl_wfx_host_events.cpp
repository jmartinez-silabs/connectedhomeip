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

/***************************************************************************
 * @file
 * @brief WFX FMAC driver main bus communication task
 *******************************************************************************
 * # License
 * <b>Copyright 2019 Silicon Laboratories Inc.
 *www.silabs.com</b>
 *******************************************************************************
 *
 * Licensed under the Apache License, Version 2.0 (the
 *"License"); you may not use this file except in
 *compliance with the License. You may obtain a copy
 *of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 *writing, software distributed under the License is
 *distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 *OR CONDITIONS OF ANY KIND, either express or
 *implied. See the License for the specific language
 *governing permissions and limitations under the
 *License.
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "em_bus.h"
#include "em_cmu.h"
#include "em_gpio.h"
#include "em_ldma.h"
#include "em_usart.h"
#include "gpiointerrupt.h"

#include "demo_config.h"

#include "AppConfig.h"
#include "sl_wfx_host.h"
#include "sl_wfx_host_events.h"
#include "sl_wfx_host_pinout.h"
#include "sl_wfx_task.h"
#include "dhcp_client.h"
#include "ethernetif.h"

#include "FreeRTOS.h"
#include "event_groups.h"
#include "task.h"

#include <platform/CHIPDeviceLayer.h>

using namespace ::chip;
using namespace ::chip::DeviceLayer;

EventGroupHandle_t sl_wfx_event_group;
TaskHandle_t wfx_events_task_handle;

// wfx_fmac_driver context
sl_wfx_context_t wifiContext;

#ifdef SL_WFX_CONFIG_SOFTAP
// Connection parameters
char softap_ssid[32]                   = SOFTAP_SSID_DEFAULT;
char softap_passkey[64]                = SOFTAP_PASSKEY_DEFAULT;
sl_wfx_security_mode_t softap_security = SOFTAP_SECURITY_DEFAULT;
uint8_t softap_channel                 = SOFTAP_CHANNEL_DEFAULT;
#endif

/* station network interface structures */
struct netif sta_netif;
extern uint8_t scan_count_web;

wfx_wifi_provision_t wifi_provision;

#define SL_WFX_MAX_STATIONS 8
#define SL_WFX_MAX_SCAN_RESULTS 50

#ifdef SL_WFX_CONFIG_SCAN
scan_result_list_t scan_list[SL_WFX_MAX_SCAN_RESULTS];
uint8_t scan_count     = 0;
uint8_t scan_count_t   = 0;
#endif

static void wfx_events_task(void * p_arg);

/* WF200 host callbacks */
static void sl_wfx_connect_callback(uint8_t * mac, uint32_t status);
static void sl_wfx_disconnect_callback(uint8_t * mac, uint16_t reason);
static void sl_wfx_generic_status_callback(sl_wfx_generic_ind_t * frame);
#ifdef SL_WFX_CONFIG_SCAN
static void sl_wfx_scan_result_callback(sl_wfx_scan_result_ind_body_t * scan_result);
static void sl_wfx_scan_complete_callback(uint32_t status);
#endif
#ifdef SL_WFX_CONFIG_SOFTAP
static void sl_wfx_start_ap_callback(uint32_t status);
static void sl_wfx_stop_ap_callback(void);
static void sl_wfx_client_connected_callback(uint8_t * mac);
static void sl_wfx_ap_client_disconnected_callback(uint32_t status, uint8_t * mac);
static void sl_wfx_ap_client_rejected_callback(uint32_t status, uint8_t * mac);
#endif
static void sl_wfx_spi_wakeup_irq_callback(uint8_t irqNumber);

/****************************************************************************
 * Init some actions pins to the WF-200 expansion board
 *****************************************************************************/
void sl_wfx_host_gpio_init(void)
{
    // Enable GPIO clock.
    CMU_ClockEnable(cmuClock_GPIO, true);

    // Configure WF200 reset pin.
    GPIO_PinModeSet(SL_WFX_HOST_PINOUT_RESET_PORT, SL_WFX_HOST_PINOUT_RESET_PIN, gpioModePushPull, 0);
    // Configure WF200 WUP pin.
    GPIO_PinModeSet(SL_WFX_HOST_PINOUT_WUP_PORT, SL_WFX_HOST_PINOUT_WUP_PIN, gpioModePushPull, 0);

    // GPIO used as IRQ.
    GPIO_PinModeSet(SL_WFX_HOST_PINOUT_SPI_WIRQ_PORT, SL_WFX_HOST_PINOUT_SPI_WIRQ_PIN, gpioModeInputPull, 0);
    CMU_OscillatorEnable(cmuOsc_LFXO, true, true);

    // Set up interrupt based callback function - trigger on both edges.
    GPIOINT_Init();
    GPIO_ExtIntConfig(SL_WFX_HOST_PINOUT_SPI_WIRQ_PORT, SL_WFX_HOST_PINOUT_SPI_WIRQ_PIN, SL_WFX_HOST_PINOUT_SPI_IRQ, true, false, true);
    GPIOINT_CallbackRegister(SL_WFX_HOST_PINOUT_SPI_IRQ, sl_wfx_spi_wakeup_irq_callback);

    // Change GPIO interrupt priority (FreeRTOS asserts unless this is done here!)
    NVIC_SetPriority(GPIO_EVEN_IRQn, 5);
    NVIC_SetPriority(GPIO_ODD_IRQn, 5);
}

/*
 * IRQ for SPI callback
 * Clear the Interrupt and wake up the task that
 * handles the actions of the interrupt (typically - wfx_bus_task ())
 */
void sl_wfx_spi_wakeup_irq_callback(uint8_t irqNumber)
{
    BaseType_t bus_task_woken;
    uint32_t interrupt_mask;

    if (irqNumber != SL_WFX_HOST_PINOUT_SPI_IRQ)
        return;
        // Get and clear all pending GPIO interrupts
    interrupt_mask = GPIO_IntGet();
    GPIO_IntClear(interrupt_mask);
    bus_task_woken = pdFALSE;
    xSemaphoreGiveFromISR(wfx_wakeup_sem, &bus_task_woken);
    vTaskNotifyGiveFromISR (wfx_bus_task_handle, &bus_task_woken);
    portYIELD_FROM_ISR (bus_task_woken);
}
/***************************************************************************
 * Creates WFX events processing task.
 ******************************************************************************/
static void wfx_events_task_start()
{
    /* create an event group to track Wi-Fi events */
    sl_wfx_event_group = xEventGroupCreate();

    if (xTaskCreate(wfx_events_task, "wfx_events", 512, NULL, 1, &wfx_events_task_handle) != pdPASS)
    {
        EFR32_LOG("Failed to create WFX wfx_events");
    }
}

/****************************************************************************
 * Called when the driver needs to post an event
 *
 * @returns Returns SL_STATUS_OK if successful,
 *SL_STATUS_FAIL otherwise
 *****************************************************************************/
sl_status_t sl_wfx_host_process_event(sl_wfx_generic_message_t * event_payload)
{
    switch (event_payload->header.id)
    {
    /******** INDICATION ********/
    case SL_WFX_STARTUP_IND_ID: {
        EFR32_LOG("WFX Startup Completed\r\n");
        PlatformMgrImpl().HandleWFXSystemEvent(WIFI_EVENT, event_payload);
        break;
    }
    case SL_WFX_CONNECT_IND_ID: {
        sl_wfx_connect_ind_t * connect_indication = (sl_wfx_connect_ind_t *) event_payload;
        sl_wfx_connect_callback(connect_indication->body.mac, connect_indication->body.status);
        PlatformMgrImpl().HandleWFXSystemEvent(WIFI_EVENT, event_payload);
        break;
    }
    case SL_WFX_DISCONNECT_IND_ID: {
        sl_wfx_disconnect_ind_t * disconnect_indication = (sl_wfx_disconnect_ind_t *) event_payload;
        sl_wfx_disconnect_callback(disconnect_indication->body.mac, disconnect_indication->body.reason);
        PlatformMgrImpl().HandleWFXSystemEvent(WIFI_EVENT, event_payload);
        break;
    }
    case SL_WFX_RECEIVED_IND_ID: {
        sl_wfx_received_ind_t * ethernet_frame = (sl_wfx_received_ind_t *) event_payload;
        if (ethernet_frame->body.frame_type == 0)
        {
            sl_wfx_host_received_frame_callback(ethernet_frame);
        }
        break;
    }
#ifdef SL_WFX_CONFIG_SCAN
    case SL_WFX_SCAN_RESULT_IND_ID: {
        sl_wfx_scan_result_ind_t * scan_result = (sl_wfx_scan_result_ind_t *) event_payload;
        sl_wfx_scan_result_callback(&scan_result->body);
        break;
    }
    case SL_WFX_SCAN_COMPLETE_IND_ID: {
        sl_wfx_scan_complete_ind_t * scan_complete = (sl_wfx_scan_complete_ind_t *) event_payload;
        sl_wfx_scan_complete_callback(scan_complete->body.status);
        break;
    }
#endif /* SL_WFX_CONFIG_SCAN */
#ifdef SL_WFX_CONFIG_SOFTAP
    case SL_WFX_START_AP_IND_ID: {
        sl_wfx_start_ap_ind_t * start_ap_indication = (sl_wfx_start_ap_ind_t *) event_payload;
        sl_wfx_start_ap_callback(start_ap_indication->body.status);
        break;
    }
    case SL_WFX_STOP_AP_IND_ID: {
        sl_wfx_stop_ap_callback();
        break;
    }
    case SL_WFX_AP_CLIENT_CONNECTED_IND_ID: {
        sl_wfx_ap_client_connected_ind_t * client_connected_indication = (sl_wfx_ap_client_connected_ind_t *) event_payload;
        sl_wfx_client_connected_callback(client_connected_indication->body.mac);
        break;
    }
    case SL_WFX_AP_CLIENT_REJECTED_IND_ID: {
        sl_wfx_ap_client_rejected_ind_t * ap_client_rejected_indication = (sl_wfx_ap_client_rejected_ind_t *) event_payload;
        sl_wfx_ap_client_rejected_callback(ap_client_rejected_indication->body.reason, ap_client_rejected_indication->body.mac);
        break;
    }
    case SL_WFX_AP_CLIENT_DISCONNECTED_IND_ID: {
        sl_wfx_ap_client_disconnected_ind_t * ap_client_disconnected_indication =
            (sl_wfx_ap_client_disconnected_ind_t *) event_payload;
        sl_wfx_ap_client_disconnected_callback(ap_client_disconnected_indication->body.reason,
                                               ap_client_disconnected_indication->body.mac);
        break;
    }
#endif /* SL_WFX_CONFIG_SOFTAP */
#ifdef SL_WFX_USE_SECURE_LINK
    case SL_WFX_SECURELINK_EXCHANGE_PUB_KEYS_IND_ID: {
        if (host_context.waited_event_id != SL_WFX_SECURELINK_EXCHANGE_PUB_KEYS_IND_ID)
        {
            memcpy((void *) &sl_wfx_context->secure_link_exchange_ind, (void *) event_payload, event_payload->header.length);
        }
        break;
    }
#endif
    case SL_WFX_GENERIC_IND_ID: {
        sl_wfx_generic_ind_t * generic_status = (sl_wfx_generic_ind_t *) event_payload;
        sl_wfx_generic_status_callback(generic_status);
        break;
    }
    case SL_WFX_EXCEPTION_IND_ID: {
        sl_wfx_exception_ind_t * firmware_exception = (sl_wfx_exception_ind_t *) event_payload;
        uint8_t * exception_tmp                     = (uint8_t *) firmware_exception;
        EFR32_LOG("firmware exception\r\n");
        for (uint16_t i = 0; i < firmware_exception->header.length; i += 16)
        {
            EFR32_LOG("hif: %.8x:", i);
            for (uint8_t j = 0; (j < 16) && ((i + j) < firmware_exception->header.length); j++)
            {
                EFR32_LOG(" %.2x", *exception_tmp);
                exception_tmp++;
            }
            EFR32_LOG("\r\n");
        }
        break;
    }
    case SL_WFX_ERROR_IND_ID: {
        sl_wfx_error_ind_t *firmware_error = (sl_wfx_error_ind_t*) event_payload;
        uint8_t *error_tmp = (uint8_t *) firmware_error;
        EFR32_LOG("firmware error %lu\r\n", firmware_error->body.type);
        for (uint16_t i = 0; i < firmware_error->header.length; i += 16) {
            EFR32_LOG("hif: %.8x:", i);
            for (uint8_t j = 0; (j < 16) && ((i + j) < firmware_error->header.length); j++) {
            EFR32_LOG(" %.2x", *error_tmp);
            error_tmp++;
            }
            EFR32_LOG("\r\n");
        }
        break;
    }
    }

    return SL_STATUS_OK;
}

#ifdef SL_WFX_CONFIG_SCAN
/****************************************************************************
 * Callback for individual scan result
 *****************************************************************************/
static void sl_wfx_scan_result_callback(sl_wfx_scan_result_ind_body_t * scan_result)
{
    scan_count++;
    EFR32_LOG("# %2d %2d  %03d %02X:%02X:%02X:%02X:%02X:%02X  %s", scan_count, scan_result->channel,
              ((int16_t)(scan_result->rcpi - 220) / 2), scan_result->mac[0], scan_result->mac[1], scan_result->mac[2],
              scan_result->mac[3], scan_result->mac[4], scan_result->mac[5], scan_result->ssid_def.ssid);
    /*Report one AP information*/
    EFR32_LOG("\r\n");
    if (scan_count <= SL_WFX_MAX_SCAN_RESULTS)
    {
        scan_list[scan_count - 1].ssid_def      = scan_result->ssid_def;
        scan_list[scan_count - 1].channel       = scan_result->channel;
        scan_list[scan_count - 1].security_mode = scan_result->security_mode;
        scan_list[scan_count - 1].rcpi          = scan_result->rcpi;
        memcpy(scan_list[scan_count - 1].mac, scan_result->mac, 6);
    }
}

/****************************************************************************
 * Callback for scan complete
 *****************************************************************************/
static void sl_wfx_scan_complete_callback(uint32_t status)
{
    (void) (status);
    /* Use scan_count value and reset it */
    scan_count_web = scan_count;
    scan_count = 0;
    xEventGroupSetBits(sl_wfx_event_group, SL_WFX_SCAN_COMPLETE);
}
#endif /* SL_WFX_CONFIG_SCAN */

/****************************************************************************
 * Callback when station connects
 *****************************************************************************/
static void sl_wfx_connect_callback(uint8_t * mac, uint32_t status)
{
    (void) (mac);
    switch (status)
    {
    case WFM_STATUS_SUCCESS: {
        EFR32_LOG("STA-Connected\r\n");
        sl_wfx_context->state =
            static_cast<sl_wfx_state_t>(static_cast<int>(sl_wfx_context->state) | static_cast<int>(SL_WFX_STA_INTERFACE_CONNECTED));
        xEventGroupSetBits(sl_wfx_event_group, SL_WFX_CONNECT);
        break;
    }
    case WFM_STATUS_NO_MATCHING_AP: {
        EFR32_LOG("WFX Connection failed, access point not found\r\n");
        break;
    }
    case WFM_STATUS_CONNECTION_ABORTED: {
        EFR32_LOG("WFX Connection aborted\r\n");
        break;
    }
    case WFM_STATUS_CONNECTION_TIMEOUT: {
        EFR32_LOG("WFX Connection timeout\r\n");
        break;
    }
    case WFM_STATUS_CONNECTION_REJECTED_BY_AP: {
        EFR32_LOG("WFX Connection rejected by the access point\r\n");
        break;
    }
    case WFM_STATUS_CONNECTION_AUTH_FAILURE: {
        EFR32_LOG("WFX Connection authentication failure\r\n");
        break;
    }
    default: {
        EFR32_LOG("WF Connection attempt error\r\n");
    }
    }
}

/****************************************************************************
 * Callback for station disconnect
 *****************************************************************************/
static void sl_wfx_disconnect_callback(uint8_t * mac, uint16_t reason)
{
    (void) (mac);
    EFR32_LOG("WFX Disconnected %d\r\n", reason);
    sl_wfx_context->state =
        static_cast<sl_wfx_state_t>(static_cast<int>(sl_wfx_context->state) & ~static_cast<int>(SL_WFX_STA_INTERFACE_CONNECTED));
    xEventGroupSetBits(sl_wfx_event_group, SL_WFX_DISCONNECT);
}

#ifdef SL_WFX_CONFIG_SOFTAP
/****************************************************************************
 * Callback for AP started
 *****************************************************************************/
static void sl_wfx_start_ap_callback(uint32_t status)
{
    if (status == 0)
    {
        EFR32_LOG("AP started\r\n");
        sl_wfx_context->state =
            static_cast<sl_wfx_state_t>(static_cast<int>(sl_wfx_context->state) | static_cast<int>(SL_WFX_AP_INTERFACE_UP));
        xEventGroupSetBits(sl_wfx_event_group, SL_WFX_START_AP);
    }
    else
    {
        EFR32_LOG("AP start failed\r\n");
        strcpy(event_log, "AP start failed");
    }
}

/****************************************************************************
 * Callback for AP stopped
 *****************************************************************************/
static void sl_wfx_stop_ap_callback(void)
{
    // TODO
    // dhcpserver_clear_stored_mac();
    EFR32_LOG("SoftAP stopped\r\n");
    sl_wfx_context->state =
        static_cast<sl_wfx_state_t>(static_cast<int>(sl_wfx_context->state) & ~static_cast<int>(SL_WFX_AP_INTERFACE_UP));
    xEventGroupSetBits(sl_wfx_event_group, SL_WFX_STOP_AP);
}


/****************************************************************************
 * Callback for client connect to AP
 *****************************************************************************/
static void sl_wfx_client_connected_callback(uint8_t * mac)
{
    EFR32_LOG("Client connected, MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    // TODO
    // EFR32_LOG("Open a web browser and go to http://%d.%d.%d.%d\r\n", ap_ip_addr0, ap_ip_addr1, ap_ip_addr2, ap_ip_addr3);
}

/****************************************************************************
 * Callback for client rejected from AP
 *****************************************************************************/
static void sl_wfx_ap_client_rejected_callback(uint32_t status, uint8_t * mac)
{
    // struct eth_addr mac_addr;
    // memcpy(&mac_addr, mac, SL_WFX_BSSID_SIZE);
    // TODO
    // dhcpserver_remove_mac(&mac_addr);
    EFR32_LOG("Client rejected, reason: %d, MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n", (int) status, mac[0], mac[1], mac[2], mac[3],
              mac[4], mac[5]);
}

/****************************************************************************
 * Callback for AP client disconnect
 *****************************************************************************/
static void sl_wfx_ap_client_disconnected_callback(uint32_t status, uint8_t * mac)
{
    // TODO
    // struct eth_addr mac_addr;
    // memcpy(&mac_addr, mac, SL_WFX_BSSID_SIZE);
    // dhcpserver_remove_mac(&mac_addr);
    EFR32_LOG("Client disconnected, reason: %d, MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n", (int) status, mac[0], mac[1], mac[2],
              mac[3], mac[4], mac[5]);
}
#endif /* SL_WFX_CONFIG_SOFTAP */

/****************************************************************************
 * Callback for generic status received
 *****************************************************************************/
static void sl_wfx_generic_status_callback(sl_wfx_generic_ind_t * frame)
{
    (void) (frame);
    EFR32_LOG("WFX Generic status received\r\n");
}

/***************************************************************************
 * WFX events processing task.
 ******************************************************************************/
static void wfx_events_task(void * p_arg)
{
    EventBits_t flags;
    (void)p_arg;

    while (1)
    {
        flags = xEventGroupWaitBits(sl_wfx_event_group,
                                    SL_WFX_CONNECT  | SL_WFX_DISCONNECT
#ifdef SL_WFX_CONFIG_SOFTAP
                                    | SL_WFX_START_AP| SL_WFX_STOP_AP
#endif /* SL_WFX_CONFIG_SOFTAP */
#ifdef SL_WFX_CONFIG_SCAN
                                    | SL_WFX_SCAN_COMPLETE
#endif /* SL_WFX_CONFIG_SCAN */
                                    |0,
                                    pdTRUE, pdFALSE, portMAX_DELAY);

        if (flags & SL_WFX_CONNECT)
        {
            lwip_set_sta_link_up();

#ifdef SLEEP_ENABLED
            if (!(wfx_get_wifi_state() & SL_WFX_AP_INTERFACE_UP))
            {
                // Enable the power save
                sl_wfx_set_power_mode(WFM_PM_MODE_PS, 1);
                sl_wfx_enable_device_power_save();
            }
#endif
        }
        if (flags & SL_WFX_DISCONNECT)
        {
            lwip_set_sta_link_down();
        }

#ifdef SL_WFX_CONFIG_SCAN
        if (flags & SL_WFX_SCAN_COMPLETE)
        {
            // we don't process this here (see scan cgi handler)
        }
#endif
    }
}

static sl_status_t wfx_init(void)
{
    /* Initialize the WF200 used by the two interfaces */
    wfx_events_task_start();
    sl_status_t status            = sl_wfx_init(&wifiContext);
    EFR32_LOG("FMAC Driver version    %s\r\n", FMAC_DRIVER_VERSION_STRING);
    switch (status)
    {
    case SL_STATUS_OK:
        wifiContext.state = SL_WFX_STARTED;
        EFR32_LOG("WF200 Firmware version %d.%d.%d\r\n", wifiContext.firmware_major, wifiContext.firmware_minor,
                wifiContext.firmware_build);
        EFR32_LOG("WF200 initialization successful\r\n");


        if (wifiContext.state == SL_WFX_STA_INTERFACE_CONNECTED)
        {
            sl_wfx_send_disconnect_command();
        }

        break;
    case SL_STATUS_WIFI_INVALID_KEY:
        EFR32_LOG("Failed to init WF200: Firmware keyset invalid\r\n");
        break;
    case SL_STATUS_WIFI_FIRMWARE_DOWNLOAD_TIMEOUT:
        EFR32_LOG("Failed to init WF200: Firmware download timeout\r\n");
        break;
    case SL_STATUS_TIMEOUT:
        EFR32_LOG("Failed to init WF200: Poll for value timeout\r\n");
        break;
    case SL_STATUS_FAIL:
        EFR32_LOG("Failed to init WF200: Error\r\n");
        break;
    default:
        EFR32_LOG("Failed to init WF200: Unknown error\r\n");
    }

    return status;
}

/*****************************************************************************
 * @brief
 *    Initializes LwIP network interface
 *
 * @param[in]
 *    none
 *
 * @return
 *    struct netif * staNetif : pointer to the Station Network interface
 *    struct netif * apNetif:  pointer to the Access Point Network interface
 ******************************************************************************/
static void Netif_Config(struct netif * staNetif, struct netif * apNetif)
{
    if (staNetif != NULL)
    {
        ip_addr_t sta_ipaddr;
        ip_addr_t sta_netmask;
        ip_addr_t sta_gw;
        /* Initialize the Station information */
        ip_addr_set_zero_ip4(&sta_ipaddr);
        ip_addr_set_zero_ip4(&sta_netmask);
        ip_addr_set_zero_ip4(&sta_gw);

        /* Add station interfaces */
        netif_add(staNetif, (const ip4_addr_t *) &sta_ipaddr, (const ip4_addr_t *) &sta_netmask, (const ip4_addr_t *) &sta_gw, NULL,
                  &sta_ethernetif_init, &tcpip_input);

        /* Registers the default network interface */
        netif_set_default(staNetif);
    }

#ifdef SL_WFX_CONFIG_SOFTAP
    if (apNetif != NULL)
    {
        // ip_addr_t ap_ipaddr;
        // ip_addr_t ap_netmask;
        // ip_addr_t ap_gw;
        // /* Initialize the SoftAP information */
        // IP_ADDR4(&ap_ipaddr, ap_ip_addr0, ap_ip_addr1, ap_ip_addr2, ap_ip_addr3);
        // IP_ADDR4(&ap_netmask, ap_netmask_addr0, ap_netmask_addr1, ap_netmask_addr2, ap_netmask_addr3);
        // IP_ADDR4(&ap_gw, ap_gw_addr0, ap_gw_addr1, ap_gw_addr2, ap_gw_addr3);
        // netif_add(apNetif, &ap_ipaddr, &ap_netmask, &ap_gw, NULL, &ap_ethernetif_init, &ethernet_input);
    }
#endif /* SL_WFX_CONFIG_SOFTAP */
}

/****************************************************************************
 * Set station link status to up.
 *****************************************************************************/
sl_status_t lwip_set_sta_link_up(void)
{
    netifapi_netif_set_up(&sta_netif);
    netifapi_netif_set_link_up(&sta_netif);
    dhcpclient_set_link_state(1);

    return SL_STATUS_OK;
}

/***************************************************************************
 * Set station link status to down.
 *****************************************************************************/
sl_status_t lwip_set_sta_link_down(void)
{
    dhcpclient_set_link_state(0);
    netifapi_netif_set_link_down(&sta_netif);
    netifapi_netif_set_down(&sta_netif);
    return SL_STATUS_OK;
}

/*****************************************************************************
 * @brief
 *   tcp ip, wfx and lwip stack and start dhcp client.
 *
 * @param[in]
 *    not used
 *
 * @return
 *    sl_status_t Shows init succes or error.
 ******************************************************************************/
sl_status_t wfx_wifi_start(void)
{
    /* Create tcp_ip stack thread */
    // tcpip_init(NULL, NULL);

    sl_status_t status = wfx_init();
    if (status == SL_STATUS_OK)
    {
        /* Initialize the LwIP stack */
         Netif_Config(&sta_netif, NULL);
        /* Start DHCP Client */
        dhcpclient_start();
    }

    return status;
}

sl_wfx_state_t wfx_get_wifi_state(void)
{
    return wifiContext.state;
}

void wfx_SetStationNetif(struct netif * newNetif)
{
    sta_netif = *newNetif;
}

struct netif * wfx_GetNetif(sl_wfx_interface_t interface)
{
    struct netif * SelectedNetif = NULL;
    if (interface == SL_WFX_STA_INTERFACE)
    {
        SelectedNetif = &sta_netif;
    }
#ifdef SL_WFX_CONFIG_SOFTAP
    else if (interface == SL_WFX_SOFTAP_INTERFACE)
    {
        // no ap currently
    }
#endif
    return SelectedNetif;
}

sl_wfx_mac_address_t wfx_get_wifi_mac_addr(sl_wfx_interface_t interface)
{
    // return Mac address used by WFX SL_WFX_STA_INTERFACE or SL_WFX_SOFTAP_INTERFACE,
    return (interface == SL_WFX_STA_INTERFACE) ? wifiContext.mac_addr_0 : wifiContext.mac_addr_1;
}

void wfx_set_wifi_provision(wfx_wifi_provision_t wifiConfig)
{
    memcpy(wifi_provision.ssid, wifiConfig.ssid, sizeof(wifiConfig.ssid));
    memcpy(wifi_provision.passkey, wifiConfig.passkey, sizeof(wifiConfig.passkey));
    wifi_provision.security = wifiConfig.security;
}

bool wfx_get_wifi_provision(wfx_wifi_provision_t * wifiConfig)
{
    bool success = false;
    if (wifiConfig != NULL)
    {
        memcpy(wifiConfig, &wifi_provision, sizeof(wfx_wifi_provision_t));
        success = true;
    }

    return success;
}

void wfx_clear_wifi_provision(void)
{
    memset(&wifi_provision, 0, sizeof(wifi_provision));
}

sl_status_t wfx_connect_to_provisionned_ap(void)
{
    sl_status_t result = SL_STATUS_NOT_AVAILABLE;
    if (wifi_provision.ssid[0] != 0)
    {
        result =
            sl_wfx_send_join_command((uint8_t *) wifi_provision.ssid, strlen(wifi_provision.ssid), NULL, 0, wifi_provision.security,
                                     1, 0, (uint8_t *) wifi_provision.passkey, strlen(wifi_provision.passkey), NULL, 0);
    }

    return result;
}
