// Copyright (c) 2020, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/**
 * @file crypto_signature_t.h
 * @brief Ed25519 signature type composed of two scalar components (L, R).
 *
 * An Ed25519 signature is a 64-byte value split into two 32-byte scalars: L (sometimes
 * called the commitment or "c" challenge) and R (the response or "r" scalar). During
 * verification, these are combined with the message hash and public key to check the
 * signature equation. Serialized as the simple concatenation L || R.
 */

#ifndef CRYPTO_SIGNATURE_T
#define CRYPTO_SIGNATURE_T

#include <types/crypto_hash_t.h>
#include <types/crypto_scalar_t.h>

/**
 * A 64-byte Ed25519 signature consisting of two scalar components (L and R).
 *
 * L is the commitment scalar (often derived from a hash of the ephemeral point and message),
 * and R is the response scalar computed from the signer's secret key. Together they satisfy
 * the verification equation that proves knowledge of the signing key without revealing it.
 */
struct crypto_signature_t final : Serializable
{
    /**
     * Constructors -- accept raw bytes (64 bytes = L || R), hex strings, or JSON.
     */

    crypto_signature_t() = default;

    crypto_signature_t(std::initializer_list<unsigned char> LR);

    explicit crypto_signature_t(const std::vector<unsigned char> &LR);

    explicit crypto_signature_t(const std::string &LR);

    JSON_STRING_CONSTRUCTOR(crypto_signature_t, fromJSON)

    /**
     * Simple operator overloads for comparison
     */

    bool operator==(const crypto_signature_t &other) const;

    bool operator!=(const crypto_signature_t &other) const;

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(Serialization::deserializer_t &reader) override;

    /**
     * Deserializes the struct from a byte array
     * @param data
     */
    void deserialize(const std::vector<unsigned char> &data) override;

    /**
     * Returns whether the signature is empty (both L and R are zero / unset).
     * @return true if the signature has not been initialized
     */
    [[nodiscard]] bool empty() const;

    /**
     * Deserializes the struct from JSON
     * @param j
     */
    JSON_FROM_FUNC(fromJSON) override;

    /**
     * Deserializes the struct from a JSON property
     * @param val
     * @param key
     */
    JSON_FROM_KEY_FUNC(fromJSON) override;

    /**
     * Computes the SHA-3 hash of the serialized signature bytes.
     * @return the 256-bit hash of this signature
     */
    [[nodiscard]] crypto_hash_t hash() const;

    /**
     * Serializes the struct to a byte array
     * @param writer
     */
    void serialize(Serialization::serializer_t &writer) const override;

    /**
     * Serializes the struct to a byte array
     * @return
     */
    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    /**
     * Returns the serialized size in bytes (always 64: 32 for L + 32 for R).
     * Use this instead of sizeof(crypto_signature_t) which includes internal padding.
     * @return the byte size of the serialized signature
     */
    [[nodiscard]] size_t size() const override;

    /**
     * Converts the structure to a JSON object
     * @param writer
     */
    JSON_TO_FUNC(toJSON) override;

    /**
     * Encodes the signature as a 128-character hexadecimal string (L || R).
     * @return the hex-encoded signature string
     */
    [[nodiscard]] std::string to_string() const override;

  private:
    /**
     * Loads a signature from a hexademical string
     * @param s
     */
    void from_string(const std::string &s);

    /**
     * Internal layout: two concatenated scalars forming the 64-byte signature S = (L || R).
     */
    struct signature_scalars
    {
        crypto_scalar_t L; ///< The commitment/challenge scalar
        crypto_scalar_t R; ///< The response scalar
    };

  public:
    /**
     * The signature's two components, accessible as LR.L and LR.R.
     */
    signature_scalars LR;
};

/**
 * Providing overloads into the std namespace such that we can easily included
 * points, scalars, and signatures in output streams
 */
namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_signature_t &value)
    {
        os << value.to_string();

        return os;
    }
} // namespace std

#endif
