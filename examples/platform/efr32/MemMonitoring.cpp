/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
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

#include "MemMonitoring.h"

#include "AppConfig.h"
#include "FreeRTOS.h"
#include <platform/CHIPDeviceLayer.h>
#include <platform/EFR32/freertos_bluetooth.h>

static StackType_t monitoringStack[MONITORING_STACK_SIZE_byte / sizeof(StackType_t)];
static StaticTask_t monitoringTaskStruct;

size_t nbAllocSuccess        = 0;
size_t nbFreeSuccess         = 0;
size_t largestBlockAllocated = 0;

typedef struct{
    void * ptr;
    size_t size;
} mallocMonitoring_t;

#define MAX_TRACKING 512

static mallocMonitoring_t mallocList[MAX_TRACKING] = {0,0};

static uint32_t HeapUsedByMallocs = 0;
static uint32_t HighestHeapUsageByMallocs = 0;

void MemMonitoring::startHeapMonitoring()
{
    xTaskCreateStatic(HeapMonitoring, "Monitoring", MONITORING_STACK_SIZE_byte / sizeof(StackType_t), NULL, 1, monitoringStack,
                      &monitoringTaskStruct);
}

void MemMonitoring::HeapMonitoring(void * pvParameter)
{

    UBaseType_t appTaskValue;
    UBaseType_t bleEventTaskValue;
    UBaseType_t bleTaskValue;
    UBaseType_t linkLayerTaskValue;
    UBaseType_t openThreadTaskValue;
    UBaseType_t eventLoopTaskValue;
    UBaseType_t lwipTaskValue;

    TaskHandle_t eventLoopHandleStruct = xTaskGetHandle(CHIP_DEVICE_CONFIG_CHIP_TASK_NAME);
    TaskHandle_t lwipHandle            = xTaskGetHandle(TCPIP_THREAD_NAME);
    TaskHandle_t otTaskHandle          = xTaskGetHandle(CHIP_DEVICE_CONFIG_THREAD_TASK_NAME);
    TaskHandle_t appTaskHandle         = xTaskGetHandle(APP_TASK_NAME);
    TaskHandle_t bleStackTaskHandle    = xTaskGetHandle(BLE_STACK_TASK_NAME);
    TaskHandle_t bleLinkTaskHandle     = xTaskGetHandle(BLE_LINK_TASK_NAME);
    TaskHandle_t bleEventTaskHandle    = xTaskGetHandle(CHIP_DEVICE_CONFIG_BLE_APP_TASK_NAME);

    while (1)
    {
        appTaskValue        = uxTaskGetStackHighWaterMark(appTaskHandle);
        bleEventTaskValue   = uxTaskGetStackHighWaterMark(bleEventTaskHandle);
        bleTaskValue        = uxTaskGetStackHighWaterMark(bleStackTaskHandle);
        linkLayerTaskValue  = uxTaskGetStackHighWaterMark(bleLinkTaskHandle);
        openThreadTaskValue = uxTaskGetStackHighWaterMark(otTaskHandle);
        eventLoopTaskValue  = uxTaskGetStackHighWaterMark(eventLoopHandleStruct);
        lwipTaskValue       = uxTaskGetStackHighWaterMark(lwipHandle);

        EFR32_LOG("=============================");
        EFR32_LOG("     ");
        EFR32_LOG("Current heap Used by allocations     %u", HeapUsedByMallocs);
        EFR32_LOG("Highest heap usage by allocations    %u", HighestHeapUsageByMallocs);
        EFR32_LOG("Largest Block allocated              %u", largestBlockAllocated);
        EFR32_LOG("Number Of Successful Alloc           %u", nbAllocSuccess);
        EFR32_LOG("Number Of Successful Frees           %u", nbFreeSuccess);
        EFR32_LOG("     ");
        EFR32_LOG("App Task most bytes ever Free         %u", (appTaskValue * 4));
        EFR32_LOG("BLE Event most bytes ever Free        %u", (bleEventTaskValue * 4));
        EFR32_LOG("BLE Stack most bytes ever Free        %u", (bleTaskValue * 4));
        EFR32_LOG("Link Layer Task most bytes ever Free  %u", (linkLayerTaskValue * 4));
        EFR32_LOG("OpenThread Task most bytes ever Free  %u", (openThreadTaskValue * 4));
        EFR32_LOG("Event Loop Task most bytes ever Free  %u", (eventLoopTaskValue * 4));
        EFR32_LOG("LWIP Task most bytes ever Free        %u", (lwipTaskValue * 4));
        EFR32_LOG("     ");
        EFR32_LOG("=============================");
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

extern "C" void memMonitoringTrackAlloc(void * ptr, size_t size)
{
    if (ptr != NULL)
    {
        nbAllocSuccess++;
        if (largestBlockAllocated < size)
        {
            largestBlockAllocated = size;
        }

        for(int i = 0; i < MAX_TRACKING; i++)
        {
            if (mallocList[i].ptr == 0)
            {
                mallocList[i].ptr = ptr;
                mallocList[i].size = size;
                HeapUsedByMallocs += size;
                break;
            }
            else if (i == (MAX_TRACKING-1))
            {
                EFR32_LOG("ERROR COULD NOT TRACK  Alloc size contribution");
            }
        }

        if (HighestHeapUsageByMallocs < HeapUsedByMallocs)
        {
            HighestHeapUsageByMallocs = HeapUsedByMallocs;
        }
    }
}

extern "C" void memMonitoringTrackFree(void * ptr, size_t size)
{
    for(int i = 0; i < MAX_TRACKING; i++)
    {
        if (mallocList[i].ptr == ptr)
        {
            HeapUsedByMallocs -= mallocList[i].size;
            mallocList[i].ptr = 0;
            mallocList[i].size = 0;
            
            break;
        }
        else if (i == (MAX_TRACKING-1))
        {
            EFR32_LOG("ERROR COULD FIND THE MALLOC PTR");
        }
    }
    nbFreeSuccess++;
}
