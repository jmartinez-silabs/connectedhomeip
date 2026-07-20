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

#include "SrpKeyPair.h"

#include <cstring>

#include <lib/support/CodeUtils.h>

namespace chip {
namespace Dnssd {
namespace Srp {

namespace {

// Uncompressed EC point marker (0x04) prefixes the 64-byte X||Y in the Matter
// P256PublicKey representation; the KEY record carries the 64 bytes without it.
constexpr size_t kUncompressedPubKeyLength = kSrpPublicKeyRawSize + 1;

// Compute the RFC 4034 (Appendix B) key tag over KEY RDATA.
uint16_t KeyTagOverRdata(const uint8_t * rdata, size_t len)
{
    uint32_t ac = 0;
    for (size_t i = 0; i < len; i++)
    {
        ac += (i & 1) ? rdata[i] : static_cast<uint32_t>(rdata[i]) << 8;
    }
    ac += (ac >> 16) & 0xFFFF;
    return static_cast<uint16_t>(ac & 0xFFFF);
}

// Build the KEY RDATA (flags/protocol/algorithm + raw public key) into `out`.
size_t BuildKeyRdata(ByteSpan rawPublicKey, uint8_t * out, size_t outSize)
{
    size_t needed = 4 + rawPublicKey.size();
    if (outSize < needed)
    {
        return 0;
    }
    out[0] = static_cast<uint8_t>(kKeyRdataFlags >> 8);
    out[1] = static_cast<uint8_t>(kKeyRdataFlags & 0xFF);
    out[2] = kKeyRdataProtocol;
    out[3] = kKeyAlgorithmEcdsaP256Sha256;
    memcpy(out + 4, rawPublicKey.data(), rawPublicKey.size());
    return needed;
}

} // namespace

CHIP_ERROR SrpKeyPair::CacheRawPublicKey()
{
    const Crypto::P256PublicKey & pubkey = mKeypair.Pubkey();
    VerifyOrReturnError(pubkey.Length() == kUncompressedPubKeyLength, CHIP_ERROR_INTERNAL);
    // Strip the leading uncompressed-point marker (0x04).
    memcpy(mRawPublicKey, pubkey.ConstBytes() + 1, kSrpPublicKeyRawSize);
    return CHIP_NO_ERROR;
}

CHIP_ERROR SrpKeyPair::InitEphemeral()
{
    VerifyOrReturnError(!mInitialized, CHIP_ERROR_INCORRECT_STATE);
    ReturnErrorOnFailure(mKeypair.Initialize(Crypto::ECPKeyTarget::ECDSA));
    ReturnErrorOnFailure(CacheRawPublicKey());
    mInitialized = true;
    return CHIP_NO_ERROR;
}

CHIP_ERROR SrpKeyPair::Init(PersistentStorageDelegate * storage, const char * storageKey)
{
    VerifyOrReturnError(storage != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(storageKey != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(!mInitialized, CHIP_ERROR_INCORRECT_STATE);

    Crypto::P256SerializedKeypair serialized;
    uint16_t size    = static_cast<uint16_t>(serialized.Capacity());
    CHIP_ERROR error = storage->SyncGetKeyValue(storageKey, serialized.Bytes(), size);

    if (error == CHIP_NO_ERROR)
    {
        ReturnErrorOnFailure(serialized.SetLength(size));
        ReturnErrorOnFailure(mKeypair.Deserialize(serialized));
    }
    else if (error == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND || error == CHIP_ERROR_KEY_NOT_FOUND)
    {
        ReturnErrorOnFailure(mKeypair.Initialize(Crypto::ECPKeyTarget::ECDSA));
        ReturnErrorOnFailure(mKeypair.Serialize(serialized));
        ReturnErrorOnFailure(storage->SyncSetKeyValue(storageKey, serialized.Bytes(),
                                                      static_cast<uint16_t>(serialized.Length())));
    }
    else
    {
        return error;
    }

    ReturnErrorOnFailure(CacheRawPublicKey());
    mInitialized = true;
    return CHIP_NO_ERROR;
}

CHIP_ERROR SrpKeyPair::Sign(ByteSpan message, MutableByteSpan & outSignature) const
{
    VerifyOrReturnError(mInitialized, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(outSignature.size() >= kSrpSignatureRawSize, CHIP_ERROR_BUFFER_TOO_SMALL);

    Crypto::P256ECDSASignature signature;
    ReturnErrorOnFailure(mKeypair.ECDSA_sign_msg(message.data(), message.size(), signature));
    VerifyOrReturnError(signature.Length() == kSrpSignatureRawSize, CHIP_ERROR_INTERNAL);

    memcpy(outSignature.data(), signature.ConstBytes(), kSrpSignatureRawSize);
    outSignature.reduce_size(kSrpSignatureRawSize);
    return CHIP_NO_ERROR;
}

uint16_t SrpKeyPair::ComputeKeyTag() const
{
    return ComputeKeyTag(GetRawPublicKey());
}

uint16_t SrpKeyPair::ComputeKeyTag(ByteSpan rawPublicKey)
{
    uint8_t rdata[4 + kSrpPublicKeyRawSize];
    size_t len = BuildKeyRdata(rawPublicKey, rdata, sizeof(rdata));
    if (len == 0)
    {
        return 0;
    }
    return KeyTagOverRdata(rdata, len);
}

CHIP_ERROR SrpKeyPair::Verify(ByteSpan rawPublicKey, ByteSpan message, ByteSpan signature)
{
    VerifyOrReturnError(rawPublicKey.size() == kSrpPublicKeyRawSize, CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(signature.size() == kSrpSignatureRawSize, CHIP_ERROR_INVALID_ARGUMENT);

    uint8_t uncompressed[kUncompressedPubKeyLength];
    uncompressed[0] = 0x04;
    memcpy(uncompressed + 1, rawPublicKey.data(), kSrpPublicKeyRawSize);
    Crypto::P256PublicKey publicKey{ FixedByteSpan<kUncompressedPubKeyLength>(uncompressed) };

    Crypto::P256ECDSASignature ecdsaSignature;
    memcpy(ecdsaSignature.Bytes(), signature.data(), kSrpSignatureRawSize);
    ReturnErrorOnFailure(ecdsaSignature.SetLength(kSrpSignatureRawSize));

    return publicKey.ECDSA_validate_msg_signature(message.data(), message.size(), ecdsaSignature);
}

} // namespace Srp
} // namespace Dnssd
} // namespace chip
