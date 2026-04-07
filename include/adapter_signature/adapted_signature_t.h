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
 * @file adapted_signature_t.h
 * @brief Post-adapt Schnorr signature: the (R', s) tuple produced by
 *        Crypto::AdapterSignature::adapt().
 */

#ifndef ADAPTED_SIGNATURE_T_H
#define ADAPTED_SIGNATURE_T_H

#include <helpers/string_helper.h>
#include <types/hash_t.h>
#include <types/point_t.h>
#include <types/scalar_t.h>

/**
 * @brief A 64-byte adapted Schnorr signature: adapted nonce point R' and response scalar s.
 *
 * Produced by Crypto::AdapterSignature::adapt() from a pre-signature and a
 * witness scalar. The verification equation (under the adapter Fiat-Shamir
 * domain) is s * G == R' + c * PK where c = H(adapter_domain, R', PK, msg).
 *
 * NOTE: this is NOT a standard Ed25519 signature. It uses a distinct
 * Fiat-Shamir domain (ADAPTER_DOMAIN_0) and must be verified with
 * Crypto::AdapterSignature::check_adapted_signature, not with
 * Crypto::Signature::check_signature.
 */
struct adapted_signature_t final : Serializable
{
    adapted_signature_t() = default;

    adapted_signature_t(std::initializer_list<unsigned char> input);

    explicit adapted_signature_t(const std::vector<unsigned char> &input);

    explicit adapted_signature_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(adapted_signature_t, fromJSON);

    adapted_signature_t(const point_t &_R_prime, const scalar_t &_s);

    explicit adapted_signature_t(Serialization::deserializer_t &reader);

    void deserialize(const std::vector<unsigned char> &data) override;

    void deserialize(Serialization::deserializer_t &reader) override;

    JSON_FROM_FUNC(fromJSON) override;

    JSON_FROM_KEY_FUNC(fromJSON) override;

    [[nodiscard]] hash_t hash() const;

    void serialize(Serialization::serializer_t &writer) const override;

    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    [[nodiscard]] size_t size() const override;

    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    [[nodiscard]] std::string to_string() const override;

    /** @brief The adapted nonce point R' = R + Y, lifted from the pre-signature unchanged. */
    point_t R_prime;

    /** @brief The adapted response scalar s = s' + y (pre-sig response plus witness). */
    scalar_t s;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const adapted_signature_t &value)
    {
        os << "AdaptedSignature [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.R_prime, "R_prime", 10) << std::endl
           << "\t" << PAD_NAMED(value.s, "s", 10);

        return os;
    }
} // namespace std

#endif
