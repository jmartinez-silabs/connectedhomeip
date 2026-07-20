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
 *   Per-device SRP signing key management.
 *
 *   The SRP client signs its DNS UPDATE messages with a per-device P-256
 *   key-pair (SIG(0), RFC 2931 / RFC 9665). The public key is advertised in a
 *   KEY record so the SRP server can authenticate subsequent updates for the
 *   same name (first-come first-served ownership).
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/CHIPError.h>
#include <lib/core/CHIPPersistentStorageDelegate.h>
#include <lib/dnssd/SrpDnsMessage.h>
#include <lib/support/Span.h>

namespace chip {
namespace Dnssd {
namespace Srp {

/// Default persistent-storage key under which the SRP host key is stored.
inline constexpr char kDefaultSrpKeyStorageKey[] = "srp/hostkey";

class SrpKeyPair
{
public:
    SrpKeyPair() = default;

    /**
     * Load the SRP key from persistent storage, generating and persisting a new
     * key-pair on first use.
     *
     * @param storage     Storage used to persist the serialized key-pair.
     * @param storageKey  Key namespace; defaults to "srp/hostkey".
     */
    CHIP_ERROR Init(PersistentStorageDelegate * storage, const char * storageKey = kDefaultSrpKeyStorageKey);

    /**
     * Generate an in-memory (non-persistent) key-pair. Intended for tests.
     */
    CHIP_ERROR InitEphemeral();

    /// @return the raw 64-byte (X||Y) public key for the KEY record RDATA.
    ByteSpan GetRawPublicKey() const { return ByteSpan(mRawPublicKey, sizeof(mRawPublicKey)); }

    /**
     * Sign a message with the host key (SIG(0)). The output receives the raw
     * 64-byte (r||s) signature.
     */
    CHIP_ERROR Sign(ByteSpan message, MutableByteSpan & outSignature) const;

    /// @return the RFC 4034 key tag over this key's KEY RDATA.
    uint16_t ComputeKeyTag() const;

    /**
     * Verify a SIG(0) signature against a raw 64-byte public key. Used by the
     * SRP server.
     *
     * @param rawPublicKey  64-byte (X||Y) public key.
     * @param message       Message that was signed.
     * @param signature     Raw 64-byte (r||s) signature.
     */
    static CHIP_ERROR Verify(ByteSpan rawPublicKey, ByteSpan message, ByteSpan signature);

    /// @return the RFC 4034 key tag over an arbitrary raw public key.
    static uint16_t ComputeKeyTag(ByteSpan rawPublicKey);

    bool IsInitialized() const { return mInitialized; }

private:
    CHIP_ERROR CacheRawPublicKey();

    Crypto::P256Keypair mKeypair;
    uint8_t mRawPublicKey[kSrpPublicKeyRawSize] = {};
    bool mInitialized                           = false;
};

} // namespace Srp
} // namespace Dnssd
} // namespace chip
