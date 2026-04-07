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
 * @file vrf_proof_t.h
 * @brief VRF proof data structures for both native and RFC 9381 variants.
 */

#ifndef VRF_PROOF_T_H
#define VRF_PROOF_T_H

#include <array>
#include <helpers/string_helper.h>
#include <types/hash_t.h>
#include <types/point_t.h>
#include <types/scalar_t.h>

/**
 * @brief A 96-byte native VRF proof: gamma point, challenge scalar, and response scalar.
 *
 * Uses the library's native hash-to-curve (Elligator + mul8) and SHA-3 for challenges.
 * The VRF output (beta) is SHA3(cofactor * gamma).
 */
struct vrf_proof_t final : Serializable
{
    vrf_proof_t() = default;

    vrf_proof_t(std::initializer_list<unsigned char> input);

    explicit vrf_proof_t(const std::vector<unsigned char> &input);

    explicit vrf_proof_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(vrf_proof_t, fromJSON);

    vrf_proof_t(const point_t &gamma, const scalar_t &c, const scalar_t &s);

    explicit vrf_proof_t(Serialization::deserializer_t &reader);

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

    /** @brief The VRF output point: Gamma = sk * H (hash-to-curve of input). */
    point_t gamma;

    /** @brief The Fiat-Shamir challenge scalar. */
    scalar_t c;

    /** @brief The response scalar (s = k + c*sk). */
    scalar_t s;
};

/**
 * @brief An 80-byte RFC 9381 VRF proof (ECVRF-EDWARDS25519-SHA512-ELL2).
 *
 * Uses SHA-512 for hash-to-curve, nonce derivation, and challenge generation.
 * The challenge is truncated to 16 bytes per the RFC specification.
 * The VRF output (beta) is SHA-512(suite_string || 0x03 || cofactor*Gamma || 0x00),
 * truncated to 32 bytes for our hash_t.
 */
struct vrf_rfc9381_proof_t final : Serializable
{
    vrf_rfc9381_proof_t() = default;

    vrf_rfc9381_proof_t(std::initializer_list<unsigned char> input);

    explicit vrf_rfc9381_proof_t(const std::vector<unsigned char> &input);

    explicit vrf_rfc9381_proof_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(vrf_rfc9381_proof_t, fromJSON);

    vrf_rfc9381_proof_t(const point_t &gamma, const std::array<unsigned char, 16> &c, const scalar_t &s);

    explicit vrf_rfc9381_proof_t(Serialization::deserializer_t &reader);

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

    /** @brief The VRF output point: Gamma = sk * H. */
    point_t gamma;

    /** @brief The 16-byte truncated challenge (per RFC 9381). */
    std::array<unsigned char, 16> c = {};

    /** @brief The response scalar (s = k - c*sk mod l). */
    scalar_t s;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const vrf_proof_t &value)
    {
        os << "VRF [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.gamma, "gamma", 17) << std::endl
           << "\t" << PAD_NAMED(value.c, "c", 17) << std::endl
           << "\t" << PAD_NAMED(value.s, "s", 17) << std::endl;

        return os;
    }

    inline ostream &operator<<(ostream &os, const vrf_rfc9381_proof_t &value)
    {
        os << "VRF-RFC9381 [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.gamma, "gamma", 17) << std::endl
           << "\tc                : " << Serialization::to_hex(value.c.data(), value.c.size()) << std::endl
           << "\t" << PAD_NAMED(value.s, "s", 17) << std::endl;

        return os;
    }
} // namespace std

#endif
