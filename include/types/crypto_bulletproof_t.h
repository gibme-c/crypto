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
//
// Inspired by the work of Sarang Noether at
// https://github.com/SarangNoether/skunkworks/tree/pybullet

/**
 * @file crypto_bulletproof_t.h
 * @brief Original Bulletproof range proof data structure with logarithmic proof size.
 */

#ifndef CRYPTO_BULLETPROOF_T
#define CRYPTO_BULLETPROOF_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * @brief An original Bulletproof range proof.
 *
 * Bulletproofs are zero-knowledge range proofs that let you prove a Pedersen-committed value
 * lies in the range [0, 2^N) without revealing the value itself. This is essential for
 * privacy-preserving transactions: you need to guarantee amounts are non-negative (no coins
 * created from thin air) without actually showing what those amounts are.
 *
 * The key innovation is logarithmic proof size -- the proof grows as O(log N) in the bit-length
 * of the range, achieved through an inner product argument (IPA) that recursively halves the
 * proof vectors. For N=64 bits, this means only ~6 rounds of L/R commitments instead of 64
 * individual bit proofs.
 *
 * Proof components:
 * - A, S: vector Pedersen commitments to the bit decomposition and blinding vectors
 * - T1, T2: commitments to the coefficients of the inner product polynomial t(x)
 * - taux, mu: blinding factor responses
 * - L, R: left/right commitments from each IPA folding round (log2(N) pairs)
 * - g, h: final folded generator scalars from the IPA
 * - t: the evaluated inner product
 *
 * Multiple values can be aggregated into a single proof, sharing the IPA overhead.
 */
struct crypto_bulletproof_t final : Serializable
{
    crypto_bulletproof_t() = default;

    crypto_bulletproof_t(std::initializer_list<unsigned char> input);

    explicit crypto_bulletproof_t(const std::vector<unsigned char> &input);

    explicit crypto_bulletproof_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_bulletproof_t, fromJSON)

    crypto_bulletproof_t(
        const crypto_point_t &A,
        const crypto_point_t &S,
        const crypto_point_t &T1,
        const crypto_point_t &T2,
        const crypto_scalar_t &taux,
        const crypto_scalar_t &mu,
        std::vector<crypto_point_t> L,
        std::vector<crypto_point_t> R,
        const crypto_scalar_t &g,
        const crypto_scalar_t &h,
        const crypto_scalar_t &t);

    explicit crypto_bulletproof_t(Serialization::deserializer_t &reader);

    /**
     * Checks that the basic construction of the proof is valid.
     *
     * Validates that L and R vectors have matching lengths, all points are on the curve,
     * and all scalars are reduced. This is a structural check only -- it does not verify
     * the zero-knowledge proof itself.
     *
     * @return true if the proof has a structurally valid construction
     */
    [[nodiscard]] bool check_construction() const;

    /**
     * Deserializes the struct from a byte array
     * @param data
     */
    void deserialize(const std::vector<unsigned char> &data) override;

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(Serialization::deserializer_t &reader) override;

    /**
     * Loads the structure from a JSON object
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
     * Provides the hash of the serialized structure
     * @return the SHA3-256 hash of the serialized byte representation
     */
    [[nodiscard]] crypto_hash_t hash() const;

    /**
     * Serializes the struct to a byte array
     * @param writer the serializer to write into
     */
    void serialize(Serialization::serializer_t &writer) const override;

    /**
     * Serializes the struct to a byte array
     * @return the serialized byte vector
     */
    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    /**
     * Returns the serialized byte size
     * @return size in bytes
     */
    [[nodiscard]] size_t size() const override;

    /**
     * Writes the structure as JSON to the provided writer
     * @param writer the JSON writer to output into
     */
    JSON_TO_FUNC(toJSON) override;

    /**
     * Returns the hex encoded serialized byte array
     * @return hex string of the serialized proof
     */
    [[nodiscard]] std::string to_string() const override;

    /** @brief A: commitment to the bit decomposition vector; S: commitment to the blinding vector. */
    crypto_point_t A, S, T1, T2;

    /** @brief taux: aggregated blinding factor for the polynomial commitment; mu: blinding for the inner product. */
    crypto_scalar_t taux, mu;

    /** @brief Left and right commitments from each round of the inner product argument.
     *  There are log2(N*M) pairs, where N is the bit-length and M is the number of aggregated values. */
    std::vector<crypto_point_t> L, R;

    /** @brief Final scalars from the IPA: g and h are the folded generator coefficients,
     *  t is the evaluated inner product t(x) = <l(x), r(x)>. */
    crypto_scalar_t g, h, t;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_bulletproof_t &value)
    {
        os << "Bulletproof [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.A, "A", 4) << std::endl
           << "\t" << PAD_NAMED(value.S, "S", 4) << std::endl
           << "\t" << PAD_NAMED(value.T1, "T1", 4) << std::endl
           << "\t" << PAD_NAMED(value.T2, "T2", 4) << std::endl
           << "\t" << PAD_NAMED(value.taux, "taux", 4) << std::endl
           << "\t" << PAD_NAMED(value.mu, "mu", 4) << std::endl
           << "\t" << PAD_STR("L", 4) << ":" << std::endl;

        for (const auto &val : value.L)
        {
            os << PAD_STR("\t", 7) << val << std::endl;
        }

        os << "\t" << PAD_STR("R", 4) << ":" << std::endl;

        for (const auto &val : value.R)
        {
            os << PAD_STR("\t", 7) << val << std::endl;
        }

        os << "\t" << PAD_NAMED(value.g, "g", 4) << std::endl
           << "\t" << PAD_NAMED(value.h, "h", 4) << std::endl
           << "\t" << PAD_NAMED(value.t, "t", 4) << std::endl;

        return os;
    }
} // namespace std

#endif
