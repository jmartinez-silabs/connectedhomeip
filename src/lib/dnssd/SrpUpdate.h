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

/**
 * @file
 *   Assembly, signing and verification of SRP DNS UPDATE messages
 *   (RFC 9665 / RFC 2136 with SIG(0) per RFC 2931).
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include <inet/IPAddress.h>
#include <lib/core/CHIPError.h>
#include <lib/dnssd/SrpDnsMessage.h>
#include <lib/dnssd/SrpKeyPair.h>
#include <lib/dnssd/platform/Dnssd.h>
#include <lib/support/Span.h>

namespace chip {
namespace Dnssd {
namespace Srp {

/// Default SRP registration domain (RFC 9665).
inline constexpr char kDefaultServiceZone[] = "default.service.arpa";

/// Size, in bytes, of the fixed portion of a SIG(0) RDATA (everything except
/// the trailing signature): type-covered(2) algorithm(1) labels(1)
/// original-ttl(4) expiration(4) inception(4) key-tag(2) signer-name-root(1).
inline constexpr size_t kSig0FixedRdataSize = 19;

/// EDNS0 option code for the Update Lease option (RFC 9665).
inline constexpr uint16_t kEdnsOptionUpdateLease = 2;

/// A service to register (or delete) via SRP, relative to the host and zone.
struct ServiceDescriptor
{
    const char * instanceLabel; ///< e.g. "B75AF9...", a single DNS label
    const char * serviceType;   ///< e.g. "_matter._tcp"
    uint16_t port;
    const TextEntry * textEntries;
    size_t textEntryCount;
    /// When true, this service is encoded with RFC 2136 delete forms instead of
    /// add forms, allowing a single UPDATE to add some services and remove
    /// others (as OpenThread's SRP client does per item state).
    bool remove = false;
};

/// Parameters used to build an SRP UPDATE message.
struct UpdateParams
{
    uint16_t transactionId;
    const char * zone;                     ///< defaults to kDefaultServiceZone when nullptr
    const char * hostLabel;                ///< single label identifying the host
    Span<const Inet::IPAddress> addresses; ///< host AAAA addresses
    Span<const ServiceDescriptor> services;
    uint32_t lease;    ///< service lease, seconds
    uint32_t keyLease; ///< key lease, seconds

    /// SIG(0) validity window (seconds since the Unix epoch, RFC 2931). When
    /// both are left 0 the signer omits a meaningful window (inception 0,
    /// expiration == keyLease) which servers that do not enforce the window
    /// accept. Set real values when a wall clock is available.
    uint32_t sig0Inception  = 0;
    uint32_t sig0Expiration = 0;
};

/**
 * Build a signed SRP UPDATE message that registers the given host and services.
 *
 * @param[in,out] outMessage  On input, the destination buffer; on success it is
 *                            resized to the encoded message length.
 * @param[in] params          Update contents.
 * @param[in] keyPair         Host key used for the SIG(0) signature.
 */
CHIP_ERROR BuildRegisterUpdate(MutableByteSpan & outMessage, const UpdateParams & params, const SrpKeyPair & keyPair);

/**
 * Build a signed SRP UPDATE message that removes all services previously
 * registered for the given host (RFC 2136 delete forms).
 */
CHIP_ERROR BuildRemoveUpdate(MutableByteSpan & outMessage, const UpdateParams & params, const SrpKeyPair & keyPair);

/// Result of parsing an SRP server's UPDATE response.
struct UpdateResponse
{
    uint16_t transactionId;
    ResponseCode rcode;
    bool hasLease;      ///< true when the server echoed an Update Lease option
    uint32_t lease;     ///< server-granted service lease, seconds (when hasLease)
    uint32_t keyLease;  ///< server-granted key lease, seconds (when hasLease)
};

/**
 * Parse an SRP UPDATE response: the transaction id, response code and (when
 * present) the server-granted lease values from the Update Lease option. The
 * granted lease governs when the client must renew, so honoring it (rather than
 * the requested value) keeps the registration alive.
 */
CHIP_ERROR ParseUpdateResponse(const uint8_t * message, size_t length, UpdateResponse & out);

/**
 * Append a SIG(0) resource record covering the message currently held by the
 * writer. The caller MUST have already written the final header with an
 * ARCOUNT that includes this SIG record.
 */
CHIP_ERROR AppendSig0(DnsWriter & writer, const SrpKeyPair & keyPair, uint32_t inception, uint32_t expiration);

/**
 * Write an EDNS0 OPT record carrying the Update Lease option (RFC 8765 style
 * LEASE + KEY-LEASE). Used both to request a lease in an UPDATE and for a server
 * to echo the granted lease in its response.
 */
CHIP_ERROR PutUpdateLeaseOption(DnsWriter & writer, uint32_t lease, uint32_t keyLease);

/**
 * Verify the trailing SIG(0) of an SRP message against a raw public key.
 *
 * @param message        The full message bytes.
 * @param length         Message length.
 * @param rawPublicKey   The 64-byte (X||Y) public key (typically taken from the
 *                       KEY record within the same message).
 */
CHIP_ERROR VerifySig0(const uint8_t * message, size_t length, ByteSpan rawPublicKey);

/// Maximum number of host addresses captured from a parsed update.
inline constexpr size_t kMaxParsedAddresses = 4;
/// Maximum number of services captured from a parsed update.
inline constexpr size_t kMaxParsedServices = 8;
/// Maximum captured TXT RDATA size per service.
inline constexpr size_t kMaxParsedTxtSize = 256;

/// A single service parsed from an SRP UPDATE.
struct ParsedService
{
    char instanceName[kMaxDottedNameSize]; ///< full instance name
    char serviceType[kMaxDottedNameSize];  ///< instance name minus the first label
    char targetHost[kMaxDottedNameSize];   ///< SRV target host name
    uint16_t port;
    uint8_t txt[kMaxParsedTxtSize];
    uint16_t txtLen;
    bool isDelete;
};

/// The contents of a parsed SRP UPDATE message (server side).
struct ParsedUpdate
{
    char hostName[kMaxDottedNameSize];
    bool hasHost;
    Inet::IPAddress addresses[kMaxParsedAddresses];
    size_t addressCount;
    uint8_t publicKey[kSrpPublicKeyRawSize];
    bool hasKey;
    uint32_t lease;
    uint32_t keyLease;
    ParsedService services[kMaxParsedServices];
    size_t serviceCount;
    /// The whole host (and all of its services) is being removed. Set by a host
    /// AAAA delete or a zero lease. Distinct from a per-service delete, which is
    /// carried by ParsedService::isDelete so a single UPDATE can add some
    /// services and remove others.
    bool hostRemoval;
};

/**
 * Parse an SRP UPDATE message into its host, key and service components. Does
 * not verify the SIG(0); callers should call VerifySig0() with the parsed
 * public key.
 */
CHIP_ERROR ParseUpdate(const uint8_t * message, size_t length, ParsedUpdate & out);

} // namespace Srp
} // namespace Dnssd
} // namespace chip
