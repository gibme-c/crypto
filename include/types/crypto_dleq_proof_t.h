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
 * @file crypto_dleq_proof_t.h
 * @brief Discrete Log Equality (DLEQ) proof data structure (Chaum-Pedersen protocol).
 *
 * A DLEQ proof demonstrates that two points A = aG and B = aH share the same discrete
 * logarithm `a` with respect to their respective base points G and H, without revealing `a`.
 */

#ifndef CRYPTO_DLEQ_PROOF_T
#define CRYPTO_DLEQ_PROOF_T

#include <types/crypto_hash_t.h>
#include <types/crypto_scalar_t.h>

/**
 * @brief A 64-byte DLEQ proof consisting of a challenge scalar `c` and response scalar `s`.
 *
 * Given public points A, B and base points G, H, the proof convinces a verifier that
 * the prover knows a scalar `a` such that A = aG and B = aH (same discrete log).
 */
struct crypto_dleq_proof_t final : Serializable
{
    crypto_dleq_proof_t() = default;

    crypto_dleq_proof_t(std::initializer_list<unsigned char> input);

    explicit crypto_dleq_proof_t(const std::vector<unsigned char> &input);

    explicit crypto_dleq_proof_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_dleq_proof_t, fromJSON);

    crypto_dleq_proof_t(const crypto_scalar_t &c, const crypto_scalar_t &s);

    explicit crypto_dleq_proof_t(Serialization::deserializer_t &reader);

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

    /** @brief The Fiat-Shamir challenge scalar. */
    crypto_scalar_t c;

    /** @brief The response scalar (s = k + c*a where k is the nonce). */
    crypto_scalar_t s;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_dleq_proof_t &value)
    {
        os << "DLEQ [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.c, "c", 17) << std::endl
           << "\t" << PAD_NAMED(value.s, "s", 17) << std::endl;

        return os;
    }
} // namespace std

#endif
