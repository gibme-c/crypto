// Copyright (c) 2020-2026, Brandon Lehmann
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
 * @file crypto_adapter_signature_t.h
 * @brief Adapter (pre-)signature data structure for Schnorr-based atomic swaps.
 *
 * An adapter signature is a "pre-signature" that becomes a valid standard signature
 * once a secret witness scalar is revealed. This enables trustless atomic swaps
 * without hash-time locks.
 */

#ifndef CRYPTO_ADAPTER_SIGNATURE_T
#define CRYPTO_ADAPTER_SIGNATURE_T

#include <types/crypto_dleq_proof_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * @brief A 128-byte adapter pre-signature: adapted nonce point, response scalar, and DLEQ proof.
 *
 * The DLEQ proof certifies that the adapted nonce was correctly constructed, binding
 * the pre-signature to the statement point Y. Once the witness y (such that Y = yG) is
 * revealed, the pre-signature can be "adapted" into a standard crypto_signature_t.
 */
struct crypto_adapter_signature_t final : Serializable
{
    crypto_adapter_signature_t() = default;

    crypto_adapter_signature_t(std::initializer_list<unsigned char> input);

    explicit crypto_adapter_signature_t(const std::vector<unsigned char> &input);

    explicit crypto_adapter_signature_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_adapter_signature_t, fromJSON);

    crypto_adapter_signature_t(
        const crypto_point_t &adapted_nonce,
        const crypto_scalar_t &s_prime,
        const crypto_dleq_proof_t &dleq);

    explicit crypto_adapter_signature_t(Serialization::deserializer_t &reader);

    void deserialize(const std::vector<unsigned char> &data) override;

    void deserialize(Serialization::deserializer_t &reader) override;

    JSON_FROM_FUNC(fromJSON) override;

    JSON_FROM_KEY_FUNC(fromJSON) override;

    [[nodiscard]] crypto_hash_t hash() const;

    void serialize(Serialization::serializer_t &writer) const override;

    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    [[nodiscard]] size_t size() const override;

    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    [[nodiscard]] std::string to_string() const override;

    /** @brief The adapted nonce point R' = R + Y (where R = rG is the raw nonce). */
    crypto_point_t adapted_nonce;

    /** @brief The pre-signature response scalar s' = r + c*sk. */
    crypto_scalar_t s_prime;

    /** @brief DLEQ proof that adapted_nonce - Y and G share the same discrete log as the raw nonce. */
    crypto_dleq_proof_t dleq;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_adapter_signature_t &value)
    {
        os << "Adapter [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.adapted_nonce, "adapted_nonce", 17) << std::endl
           << "\t" << PAD_NAMED(value.s_prime, "s_prime", 17) << std::endl
           << "\t" << value.dleq;

        return os;
    }
} // namespace std

#endif
