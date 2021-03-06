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

// THIS FILE IS GENERATED BY ZAP

// Prevent multiple inclusion
#pragma once

#include <controller/CHIPCluster.h>
#include <core/CHIPCallback.h>
#include <lib/support/Span.h>

namespace chip {
namespace Controller {

constexpr ClusterId kFlowMeasurementClusterId        = 0x0404;
constexpr ClusterId kPressureMeasurementClusterId    = 0x0403;
constexpr ClusterId kTemperatureMeasurementClusterId = 0x0402;

class DLL_EXPORT FlowMeasurementCluster : public ClusterBase
{
public:
    FlowMeasurementCluster() : ClusterBase(kFlowMeasurementClusterId) {}
    ~FlowMeasurementCluster() {}

    // Cluster Attributes
    CHIP_ERROR DiscoverAttributes(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMinMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMaxMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeClusterRevision(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ConfigureAttributeMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback,
                                               uint16_t minInterval, uint16_t maxInterval, int16_t change);
    CHIP_ERROR ReportAttributeMeasuredValue(Callback::Cancelable * onReportCallback);
};

class DLL_EXPORT PressureMeasurementCluster : public ClusterBase
{
public:
    PressureMeasurementCluster() : ClusterBase(kPressureMeasurementClusterId) {}
    ~PressureMeasurementCluster() {}

    // Cluster Attributes
    CHIP_ERROR DiscoverAttributes(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMinMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMaxMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeClusterRevision(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ConfigureAttributeMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback,
                                               uint16_t minInterval, uint16_t maxInterval, int16_t change);
    CHIP_ERROR ReportAttributeMeasuredValue(Callback::Cancelable * onReportCallback);
};

class DLL_EXPORT TemperatureMeasurementCluster : public ClusterBase
{
public:
    TemperatureMeasurementCluster() : ClusterBase(kTemperatureMeasurementClusterId) {}
    ~TemperatureMeasurementCluster() {}

    // Cluster Attributes
    CHIP_ERROR DiscoverAttributes(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMinMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeMaxMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ReadAttributeClusterRevision(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback);
    CHIP_ERROR ConfigureAttributeMeasuredValue(Callback::Cancelable * onSuccessCallback, Callback::Cancelable * onFailureCallback,
                                               uint16_t minInterval, uint16_t maxInterval, int16_t change);
    CHIP_ERROR ReportAttributeMeasuredValue(Callback::Cancelable * onReportCallback);
};

} // namespace Controller
} // namespace chip
