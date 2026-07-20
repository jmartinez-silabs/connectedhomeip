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

#include "InfraDnssd.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <crypto/RandUtils.h>
#include <inet/InetInterface.h>
#include <lib/dnssd/SrpDnsMessage.h>
#include <lib/dnssd/SrpUpdate.h>
#include <lib/support/CHIPMemString.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <system/SystemPacketBuffer.h>

namespace chip {
namespace Dnssd {

namespace {
InfraDnssdManager sInstance;

// Compose the full DNS-SD service type (e.g. "_matter._tcp") from a DnssdService.
CHIP_ERROR MakeServiceType(const DnssdService & service, char * out, size_t outSize)
{
    const char * protocol = (service.mProtocol == DnssdServiceProtocol::kDnssdProtocolTcp) ? "_tcp" : "_udp";
    int written           = snprintf(out, outSize, "%s.%s", service.mType, protocol);
    VerifyOrReturnError(written > 0 && static_cast<size_t>(written) < outSize, CHIP_ERROR_BUFFER_TOO_SMALL);
    return CHIP_NO_ERROR;
}

} // namespace

InfraDnssdManager & InfraDnssdManager::Instance()
{
    return sInstance;
}

CHIP_ERROR InfraDnssdManager::Init(InfraProviderDelegate * delegate)
{
    VerifyOrReturnError(delegate != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(!mInitialized, CHIP_ERROR_INCORRECT_STATE);

    mDelegate    = delegate;
    mInitialized = true;

    ChipLogProgress(Discovery, "InfraDnssdManager initialized");
    return CHIP_NO_ERROR;
}

void InfraDnssdManager::Shutdown()
{
    if (!mInitialized)
    {
        return;
    }

    CancelTimers();

    if (!mUdpEndPoint.IsNull())
    {
        mUdpEndPoint->Close();
        mUdpEndPoint = nullptr;
    }

    mDelegate           = nullptr;
    mCurrentProvider    = {};
    mInitialized        = false;
    mUpdateInFlight     = false;
    mResendPending      = false;
    mConsecutiveFailures = 0;
    mRetryWaitMs        = kMinRetryWaitMs;

    ChipLogProgress(Discovery, "InfraDnssdManager shut down");
}

CHIP_ERROR InfraDnssdManager::SetHostLabel(const char * hostLabel)
{
    VerifyOrReturnError(hostLabel != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(strlen(hostLabel) < sizeof(mHostLabel), CHIP_ERROR_INVALID_ARGUMENT);
    Platform::CopyString(mHostLabel, hostLabel);
    mHostLabelSet = true;
    return CHIP_NO_ERROR;
}

CHIP_ERROR InfraDnssdManager::SetHostAddresses(Span<const Inet::IPAddress> addresses)
{
    VerifyOrReturnError(addresses.size() <= kMaxHostAddresses, CHIP_ERROR_BUFFER_TOO_SMALL);
    mHostAddressCount = 0;
    for (const Inet::IPAddress & address : addresses)
    {
        mHostAddresses[mHostAddressCount++] = address;
    }
    mHostAddressesExplicit = true;
    return CHIP_NO_ERROR;
}

void InfraDnssdManager::CollectHostAddresses()
{
    mHostAddressCount = 0;

    Inet::InterfaceAddressIterator it;
    for (; it.HasCurrent() && mHostAddressCount < kMaxHostAddresses; it.Next())
    {
        if (!it.IsUp() || it.IsLoopback())
        {
            continue;
        }

        Inet::IPAddress address;
        if (it.GetAddress(address) != CHIP_NO_ERROR)
        {
            continue;
        }

        // Only advertise routable IPv6 addresses; link-local addresses are not
        // reachable by an off-link SRP server / resolver.
        if (!address.IsIPv6() || address.IsIPv6LinkLocal() || address.IsIPv6Multicast())
        {
            continue;
        }

        mHostAddresses[mHostAddressCount++] = address;
    }
}

bool InfraDnssdManager::HasProvider() const
{
    return mCurrentProvider.type != InfraProviderType::kNone;
}

const InfraProvider & InfraDnssdManager::GetCurrentProvider() const
{
    return mCurrentProvider;
}

size_t InfraDnssdManager::GetServiceCount() const
{
    size_t count = 0;
    for (const ServiceEntry & entry : mServices)
    {
        if (entry.state == ServiceState::kActive)
        {
            count++;
        }
    }
    return count;
}

InfraDnssdManager::ServiceEntry * InfraDnssdManager::FindService(const char * instanceLabel, const char * serviceType)
{
    for (ServiceEntry & entry : mServices)
    {
        if (entry.state != ServiceState::kFree && strcmp(entry.instanceLabel, instanceLabel) == 0 &&
            strcmp(entry.serviceType, serviceType) == 0)
        {
            return &entry;
        }
    }
    return nullptr;
}

InfraDnssdManager::ServiceEntry * InfraDnssdManager::AllocateService()
{
    for (ServiceEntry & entry : mServices)
    {
        if (entry.state == ServiceState::kFree)
        {
            return &entry;
        }
    }
    return nullptr;
}

CHIP_ERROR InfraDnssdManager::RegisterService(const DnssdService & service)
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(HasProvider(), CHIP_ERROR_NOT_CONNECTED);

    char serviceType[kMaxServiceTypeSize];
    ReturnErrorOnFailure(MakeServiceType(service, serviceType, sizeof(serviceType)));

    ServiceEntry * entry = FindService(service.mName, serviceType);
    if (entry == nullptr)
    {
        entry = AllocateService();
        VerifyOrReturnError(entry != nullptr, CHIP_ERROR_NO_MEMORY);
    }

    entry->state = ServiceState::kActive;
    Platform::CopyString(entry->instanceLabel, service.mName);
    Platform::CopyString(entry->serviceType, serviceType);
    entry->port           = service.mPort;
    entry->textEntryCount = 0;

    size_t entryCount = (service.mTextEntries != nullptr) ? std::min(service.mTextEntrySize, kMaxTextEntriesPerService) : 0;
    for (size_t i = 0; i < entryCount; i++)
    {
        const TextEntry & src   = service.mTextEntries[i];
        StoredTextEntry & stored = entry->textEntries[entry->textEntryCount];
        if (src.mKey == nullptr || strlen(src.mKey) >= sizeof(stored.key))
        {
            continue;
        }
        Platform::CopyString(stored.key, src.mKey);
        stored.hasValue = (src.mData != nullptr);
        stored.valueLen = 0;
        if (stored.hasValue)
        {
            size_t copyLen = std::min(src.mDataSize, sizeof(stored.value));
            memcpy(stored.value, src.mData, copyLen);
            stored.valueLen = static_cast<uint16_t>(copyLen);
        }
        entry->textEntryCount++;
    }

    ChipLogProgress(Discovery, "InfraDnssd: queued SRP registration %s.%s port %u", entry->instanceLabel, entry->serviceType,
                    entry->port);
    return CHIP_NO_ERROR;
}

CHIP_ERROR InfraDnssdManager::RemoveService(const char * instanceName, const char * serviceType)
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(HasProvider(), CHIP_ERROR_NOT_CONNECTED);
    VerifyOrReturnError(instanceName != nullptr && serviceType != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    // Mark the service for removal (its delete records are sent on the next
    // update and the slot is freed once the server acknowledges). The actual
    // DNS UPDATE is emitted by FinalizeServiceUpdate().
    ServiceEntry * entry = FindService(instanceName, serviceType);
    if (entry != nullptr)
    {
        entry->state = ServiceState::kToRemove;
    }
    ChipLogProgress(Discovery, "InfraDnssd: queued SRP removal %s %s", instanceName, serviceType);
    return CHIP_NO_ERROR;
}

CHIP_ERROR InfraDnssdManager::RemoveAllServices()
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);

    if (!HasProvider())
    {
        // Nothing registered with a provider; the caller falls back to mDNS.
        for (ServiceEntry & entry : mServices)
        {
            entry.state = ServiceState::kFree;
        }
        return CHIP_NO_ERROR;
    }

    // Send a whole-host removal (deletes the host and all of its services). The
    // slots are freed only once the server acknowledges, so a lost removal is
    // retried.
    return RequestSend(/*removeHost=*/true);
}

CHIP_ERROR InfraDnssdManager::FinalizeServiceUpdate()
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);

    if (!HasProvider())
    {
        // Caller should fall back to mDNS.
        return CHIP_NO_ERROR;
    }

    return RequestSend(/*removeHost=*/false);
}

CHIP_ERROR InfraDnssdManager::EnsureKeyPair()
{
    if (mKeyPairReady)
    {
        return CHIP_NO_ERROR;
    }
    if (mStorage != nullptr)
    {
        ReturnErrorOnFailure(mKeyPair.Init(mStorage));
    }
    else
    {
        ReturnErrorOnFailure(mKeyPair.InitEphemeral());
    }
    mKeyPairReady = true;
    return CHIP_NO_ERROR;
}

size_t InfraDnssdManager::CollectActive(Srp::ServiceDescriptor * descriptors,
                                        TextEntry (*textEntries)[kMaxTextEntriesPerService], size_t maxServices,
                                        bool includeRemovals) const
{
    size_t serviceCount = 0;
    for (const ServiceEntry & entry : mServices)
    {
        if (entry.state == ServiceState::kFree)
        {
            continue;
        }
        const bool remove = (entry.state == ServiceState::kToRemove);
        if (remove && !includeRemovals)
        {
            continue;
        }
        if (serviceCount >= maxServices)
        {
            break;
        }
        for (size_t i = 0; i < entry.textEntryCount; i++)
        {
            textEntries[serviceCount][i].mKey      = entry.textEntries[i].key;
            textEntries[serviceCount][i].mData     = entry.textEntries[i].hasValue ? entry.textEntries[i].value : nullptr;
            textEntries[serviceCount][i].mDataSize = entry.textEntries[i].valueLen;
        }
        descriptors[serviceCount].instanceLabel  = entry.instanceLabel;
        descriptors[serviceCount].serviceType    = entry.serviceType;
        descriptors[serviceCount].port           = entry.port;
        descriptors[serviceCount].textEntries    = textEntries[serviceCount];
        descriptors[serviceCount].textEntryCount = entry.textEntryCount;
        descriptors[serviceCount].remove         = remove;
        serviceCount++;
    }
    return serviceCount;
}

void InfraDnssdManager::PopulateSig0Window(Srp::UpdateParams & params) const
{
    // RFC 2931 SIG(0) validity window in seconds since the Unix epoch. Only
    // meaningful when the device has a real-time clock; otherwise both stay 0
    // and the signer falls back to a window servers that do not enforce it
    // accept.
    System::Clock::Microseconds64 realTime;
    if (System::SystemClock().GetClock_RealTime(realTime) == CHIP_NO_ERROR)
    {
        uint32_t nowSeconds   = static_cast<uint32_t>(realTime.count() / 1000000);
        params.sig0Inception  = (nowSeconds > kRenewGuardSeconds) ? (nowSeconds - kRenewGuardSeconds) : 0;
        params.sig0Expiration = nowSeconds + mKeyLease;
    }
}

CHIP_ERROR InfraDnssdManager::RequestSend(bool removeHost)
{
    // Coalesce with any update already in flight: remember the latest desired
    // action and send it once the outstanding update completes.
    if (mUpdateInFlight)
    {
        mResendPending      = true;
        mResendIsRemoveHost = removeHost;
        return CHIP_NO_ERROR;
    }
    return SendUpdate(removeHost);
}

CHIP_ERROR InfraDnssdManager::SendUpdate(bool removeHost)
{
    VerifyOrReturnError(mHostLabelSet, CHIP_ERROR_INCORRECT_STATE);
    ReturnErrorOnFailure(EnsureKeyPair());

    // A fresh send supersedes any pending retry.
    if (mRetryScheduled && mEndPointManager != nullptr)
    {
        mEndPointManager->SystemLayer().CancelTimer(OnRetryTimer, this);
        mRetryScheduled = false;
    }

    // When host addresses were not supplied explicitly, refresh them from the
    // current interface addresses so the registration carries valid AAAA records.
    if (!mHostAddressesExplicit)
    {
        CollectHostAddresses();
    }

    // A registration with no host address is invalid (the host would have no
    // reachable AAAA record); refuse to send it so the caller can fall back to
    // mDNS. Removals do not carry addresses, so they are exempt.
    VerifyOrReturnError(removeHost || mHostAddressCount > 0, CHIP_ERROR_INCORRECT_STATE);

    Srp::ServiceDescriptor descriptors[CHIP_DEVICE_CONFIG_WIFI_SRP_MAX_SERVICES];
    static_assert(kMaxTextEntriesPerService > 0, "at least one text entry slot required");
    TextEntry textEntries[CHIP_DEVICE_CONFIG_WIFI_SRP_MAX_SERVICES][kMaxTextEntriesPerService];

    // A whole-host removal deletes every known service; an incremental update
    // carries active services as adds and kToRemove services as deletes.
    size_t serviceCount =
        CollectActive(descriptors, textEntries, CHIP_DEVICE_CONFIG_WIFI_SRP_MAX_SERVICES, /*includeRemovals=*/true);

    Srp::UpdateParams params;
    params.transactionId = ++mTransactionId;
    params.zone          = Srp::kDefaultServiceZone;
    params.hostLabel     = mHostLabel;
    params.addresses     = Span<const Inet::IPAddress>(mHostAddresses, mHostAddressCount);
    params.services      = Span<const Srp::ServiceDescriptor>(descriptors, serviceCount);
    params.lease         = removeHost ? 0 : mLease;
    params.keyLease      = removeHost ? 0 : mKeyLease;
    PopulateSig0Window(params);

    uint8_t buffer[kMaxSrpMessageSize];
    MutableByteSpan message(buffer);
    if (removeHost)
    {
        ReturnErrorOnFailure(Srp::BuildRemoveUpdate(message, params, mKeyPair));
    }
    else
    {
        ReturnErrorOnFailure(Srp::BuildRegisterUpdate(message, params, mKeyPair));
    }

    ReturnErrorOnFailure(SendMessage(message.data(), message.size()));

    mUpdateInFlight       = true;
    mInFlightIsRemoveHost = removeHost;
    mInFlightTxnId        = params.transactionId;
    ArmResponseTimeout();
    return CHIP_NO_ERROR;
}

CHIP_ERROR InfraDnssdManager::SendMessage(const uint8_t * data, size_t length)
{
    VerifyOrReturnError(mEndPointManager != nullptr, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(HasProvider(), CHIP_ERROR_NOT_CONNECTED);

    if (mUdpEndPoint.IsNull())
    {
        ReturnErrorOnFailure(mEndPointManager->NewEndPoint(mUdpEndPoint));
        ReturnErrorOnFailure(mUdpEndPoint->Bind(Inet::IPAddressType::kIPv6, Inet::IPAddress::Any, 0));
        ReturnErrorOnFailure(mUdpEndPoint->Listen(OnUdpMessageReceived, OnUdpReceiveError, this));
    }

    System::PacketBufferHandle buffer = System::PacketBufferHandle::NewWithData(data, length);
    VerifyOrReturnError(!buffer.IsNull(), CHIP_ERROR_NO_MEMORY);

    ChipLogProgress(Discovery, "InfraDnssd: sending SRP UPDATE (%u bytes) to provider port %u",
                    static_cast<unsigned>(length), mCurrentProvider.port);
    return mUdpEndPoint->SendTo(mCurrentProvider.address, mCurrentProvider.port, std::move(buffer));
}

void InfraDnssdManager::ArmResponseTimeout()
{
    VerifyOrReturn(mEndPointManager != nullptr);
    if (mResponseScheduled)
    {
        mEndPointManager->SystemLayer().CancelTimer(OnResponseTimeoutTimer, this);
        mResponseScheduled = false;
    }
    // Add small jitter so retransmissions from many devices do not synchronize.
    uint32_t jitter    = Crypto::GetRandU32() % (kRetryJitterMs + 1);
    CHIP_ERROR err     = mEndPointManager->SystemLayer().StartTimer(
        System::Clock::Milliseconds32(kResponseTimeoutMs + jitter), OnResponseTimeoutTimer, this);
    if (err == CHIP_NO_ERROR)
    {
        mResponseScheduled = true;
    }
}

void InfraDnssdManager::CancelTimers()
{
    VerifyOrReturn(mEndPointManager != nullptr);
    System::Layer & layer = mEndPointManager->SystemLayer();
    if (mRenewalScheduled)
    {
        layer.CancelTimer(OnRenewalTimer, this);
        mRenewalScheduled = false;
    }
    if (mResponseScheduled)
    {
        layer.CancelTimer(OnResponseTimeoutTimer, this);
        mResponseScheduled = false;
    }
    if (mRetryScheduled)
    {
        layer.CancelTimer(OnRetryTimer, this);
        mRetryScheduled = false;
    }
}

void InfraDnssdManager::ScheduleRenewal(uint32_t leaseSeconds)
{
    VerifyOrReturn(mEndPointManager != nullptr);
    if (mRenewalScheduled)
    {
        mEndPointManager->SystemLayer().CancelTimer(OnRenewalTimer, this);
        mRenewalScheduled = false;
    }
    // Renew early, before the granted lease elapses (guard interval). For very
    // short leases fall back to half the interval.
    uint32_t renewSeconds =
        (leaseSeconds > kRenewGuardSeconds) ? (leaseSeconds - kRenewGuardSeconds) : ((leaseSeconds > 1) ? leaseSeconds / 2 : 1);
    CHIP_ERROR err = mEndPointManager->SystemLayer().StartTimer(System::Clock::Seconds32(renewSeconds), OnRenewalTimer, this);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssd: failed to schedule SRP renewal: %" CHIP_ERROR_FORMAT, err.Format());
        return;
    }
    mRenewalScheduled = true;
}

void InfraDnssdManager::OnUpdateAccepted(uint32_t grantedLease, uint32_t grantedKeyLease)
{
    mConsecutiveFailures = 0;
    mRetryWaitMs         = kMinRetryWaitMs;

    if (mInFlightIsRemoveHost)
    {
        // The host and all services were removed server-side; drop local state.
        for (ServiceEntry & entry : mServices)
        {
            entry.state = ServiceState::kFree;
        }
    }
    else
    {
        // Free the services that were pending removal; the rest remain active.
        for (ServiceEntry & entry : mServices)
        {
            if (entry.state == ServiceState::kToRemove)
            {
                entry.state = ServiceState::kFree;
            }
        }
        // Honor the server-granted lease (fall back to the requested value).
        uint32_t lease = (grantedLease != 0) ? grantedLease : mLease;
        if (GetServiceCount() > 0)
        {
            ScheduleRenewal(lease);
        }
    }

    mUpdateInFlight = false;
    if (mResendPending)
    {
        mResendPending = false;
        CHIP_ERROR err = SendUpdate(mResendIsRemoveHost);
        if (err != CHIP_NO_ERROR)
        {
            ChipLogError(Discovery, "InfraDnssd: coalesced SRP update failed: %" CHIP_ERROR_FORMAT, err.Format());
        }
    }
}

void InfraDnssdManager::OnUpdateFailed(const char * reason)
{
    mUpdateInFlight = false;
    mConsecutiveFailures++;
    ChipLogError(Discovery, "InfraDnssd: SRP update failed (%s), attempt %u", reason,
                 static_cast<unsigned>(mConsecutiveFailures));

    if (mConsecutiveFailures >= kMaxConsecutiveFailures)
    {
        // Give up on this provider so the device can fail over to another
        // provider or fall back to mDNS (DnssdImpl routes to mDNS when there is
        // no provider).
        ChipLogError(Discovery, "InfraDnssd: dropping provider after %u consecutive failures",
                     static_cast<unsigned>(mConsecutiveFailures));
        mConsecutiveFailures = 0;
        mRetryWaitMs         = kMinRetryWaitMs;
        OnProviderUnreachable();
        return;
    }

    VerifyOrReturn(mEndPointManager != nullptr && HasProvider());
    if (mRetryScheduled)
    {
        mEndPointManager->SystemLayer().CancelTimer(OnRetryTimer, this);
        mRetryScheduled = false;
    }
    uint32_t jitter = Crypto::GetRandU32() % (kRetryJitterMs + 1);
    CHIP_ERROR err  = mEndPointManager->SystemLayer().StartTimer(System::Clock::Milliseconds32(mRetryWaitMs + jitter),
                                                                OnRetryTimer, this);
    if (err == CHIP_NO_ERROR)
    {
        mRetryScheduled = true;
    }
    // Grow the retry interval for the next attempt (exponential backoff, capped).
    uint64_t next = (static_cast<uint64_t>(mRetryWaitMs) * kRetryGrowthNumerator) / kRetryGrowthDenominator;
    mRetryWaitMs  = static_cast<uint32_t>(std::min<uint64_t>(next, kMaxRetryWaitMs));
}

void InfraDnssdManager::OnRenewalTimer(System::Layer * layer, void * context)
{
    auto * self = static_cast<InfraDnssdManager *>(context);
    if (self == nullptr || !self->mInitialized)
    {
        return;
    }
    self->mRenewalScheduled = false;
    if (!self->HasProvider())
    {
        return;
    }
    CHIP_ERROR err = self->RequestSend(/*removeHost=*/false);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssd: SRP renewal failed: %" CHIP_ERROR_FORMAT, err.Format());
    }
}

void InfraDnssdManager::OnResponseTimeoutTimer(System::Layer * layer, void * context)
{
    auto * self = static_cast<InfraDnssdManager *>(context);
    VerifyOrReturn(self != nullptr && self->mInitialized);
    self->mResponseScheduled = false;
    if (!self->mUpdateInFlight)
    {
        return;
    }
    self->OnUpdateFailed("response timeout");
}

void InfraDnssdManager::OnRetryTimer(System::Layer * layer, void * context)
{
    auto * self = static_cast<InfraDnssdManager *>(context);
    VerifyOrReturn(self != nullptr && self->mInitialized);
    self->mRetryScheduled = false;
    if (!self->HasProvider())
    {
        return;
    }
    CHIP_ERROR err = self->SendUpdate(self->mInFlightIsRemoveHost);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssd: SRP retry send failed: %" CHIP_ERROR_FORMAT, err.Format());
        self->OnUpdateFailed("retry send error");
    }
}

void InfraDnssdManager::OnUdpMessageReceived(Inet::UDPEndPoint * endPoint, System::PacketBufferHandle && msg,
                                             const Inet::IPPacketInfo * pktInfo)
{
    auto * self = (endPoint != nullptr) ? static_cast<InfraDnssdManager *>(endPoint->mAppState) : nullptr;
    VerifyOrReturn(self != nullptr && self->mInitialized && !msg.IsNull());

    Srp::UpdateResponse response;
    if (Srp::ParseUpdateResponse(msg->Start(), msg->DataLength(), response) != CHIP_NO_ERROR)
    {
        ChipLogError(Discovery, "InfraDnssd: failed to parse SRP response");
        return;
    }

    // Ignore stale responses that do not match the outstanding transaction.
    if (!self->mUpdateInFlight || response.transactionId != self->mInFlightTxnId)
    {
        return;
    }

    if (self->mResponseScheduled && self->mEndPointManager != nullptr)
    {
        self->mEndPointManager->SystemLayer().CancelTimer(OnResponseTimeoutTimer, self);
        self->mResponseScheduled = false;
    }

    if (response.rcode == Srp::ResponseCode::kNoError)
    {
        uint32_t lease    = response.hasLease ? response.lease : self->mLease;
        uint32_t keyLease = response.hasLease ? response.keyLease : self->mKeyLease;
        ChipLogProgress(Discovery, "InfraDnssd: SRP UPDATE accepted (lease %us, key-lease %us)", static_cast<unsigned>(lease),
                        static_cast<unsigned>(keyLease));
        self->OnUpdateAccepted(lease, keyLease);
    }
    else
    {
        ChipLogError(Discovery, "InfraDnssd: SRP UPDATE rejected, rcode=%u", static_cast<unsigned>(response.rcode));
        self->OnUpdateFailed("server rejected update");
    }
}

void InfraDnssdManager::OnUdpReceiveError(Inet::UDPEndPoint * endPoint, CHIP_ERROR error, const Inet::IPPacketInfo * pktInfo)
{
    ChipLogError(Discovery, "InfraDnssd: SRP UDP receive error: %" CHIP_ERROR_FORMAT, error.Format());
}

void InfraDnssdManager::OnRouterAdvertisementReceived(const Inet::IPAddress & sourceAddress, uint16_t routerLifetime,
                                                      bool hasInfraFlag, bool hasSnacFlag)
{
    if (!mInitialized)
    {
        return;
    }

    InfraProvider candidate;
    candidate.address = sourceAddress;
    candidate.port    = 53; // Default DNS port; SRP port may be discovered from RA option

    if (hasInfraFlag && routerLifetime > 0)
    {
        candidate.type = InfraProviderType::kInfraRouter;
        ChipLogProgress(Discovery, "InfraDnssd: Discovered Infrastructure Router via RA");
    }
    else if (hasSnacFlag)
    {
        candidate.type = InfraProviderType::kSnacRouter;
        ChipLogProgress(Discovery, "InfraDnssd: Discovered SNAC Router via RA");
    }
    else
    {
        return;
    }

    UpdatePreferredProvider(candidate);
}

void InfraDnssdManager::OnAdHocProviderDiscovered(const Inet::IPAddress & address, uint16_t port)
{
    if (!mInitialized)
    {
        return;
    }

    InfraProvider candidate;
    candidate.type    = InfraProviderType::kAdHocProvider;
    candidate.address = address;
    candidate.port    = port;

    ChipLogProgress(Discovery, "InfraDnssd: Discovered Ad-hoc SRP provider via mDNS");

    UpdatePreferredProvider(candidate);
}

void InfraDnssdManager::OnProviderUnreachable()
{
    if (!mInitialized)
    {
        return;
    }

    ChipLogProgress(Discovery, "InfraDnssd: Current provider unreachable, resetting");

    CancelTimers();
    mUpdateInFlight = false;
    mResendPending  = false;
    mCurrentProvider = {};

    if (mDelegate != nullptr)
    {
        mDelegate->OnInfraProviderLost();
    }
}

void InfraDnssdManager::UpdatePreferredProvider(const InfraProvider & candidate)
{
    // Lower enum value = higher priority
    if (candidate.type < mCurrentProvider.type || mCurrentProvider.type == InfraProviderType::kNone)
    {
        mCurrentProvider = candidate;

        ChipLogProgress(Discovery, "InfraDnssd: Provider updated to type %u", static_cast<unsigned>(candidate.type));

        if (mDelegate != nullptr)
        {
            mDelegate->OnInfraProviderAvailable(mCurrentProvider);
        }
    }
}

} // namespace Dnssd
} // namespace chip
