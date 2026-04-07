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
//
// Inspired by the work of Sarang Noether at
// https://github.com/SarangNoether/skunkworks/tree/pybullet-plus

/**
 * @file bulletproof_plus_t.h
 * @brief Bulletproofs+ range proof data structure with improved proof size and verification speed.
 */

#ifndef BULLETPROOF_PLUS_T_H
#define BULLETPROOF_PLUS_T_H

#include <helpers/string_helper.h>
#include <types/hash_t.h>
#include <types/point_t.h>
#include <types/scalar_t.h>

/**
 * @brief A Bulletproofs+ range proof -- improved version with smaller proofs and faster verification.
 *
 * Bulletproofs+ builds on the original Bulletproofs by replacing the standard inner product
 * argument with a weighted inner product argument (WIP). This seemingly small change yields
 * concrete improvements: proofs are about 96 bytes smaller (for single-value N=64 proofs) and
 * verification is noticeably faster, since the WIP structure allows more efficient batching of
 * the multi-scalar multiplications during verification.
 *
 * Like original Bulletproofs, these prove a Pedersen-committed value lies in [0, 2^N) without
 * revealing the value. Multiple values can be aggregated into a single proof.
 *
 * Proof components:
 * - A: vector Pedersen commitment to the combined bit-decomposition and blinding
 * - A1, B: auxiliary commitments from the weighted inner product argument
 * - r1, s1, d1: final response scalars from the WIP
 * - L, R: left/right commitments from each WIP folding round (log2(N*M) pairs)
 *
 * The reduced scalar count (3 vs 5 in original BP) is the main source of the size savings.
 */
struct bulletproof_plus_t final : Serializable
{
    bulletproof_plus_t() = default;

    bulletproof_plus_t(std::initializer_list<unsigned char> input);

    explicit bulletproof_plus_t(const std::vector<unsigned char> &input);

    explicit bulletproof_plus_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(bulletproof_plus_t, fromJSON)

    bulletproof_plus_t(
        const point_t &A,
        const point_t &A1,
        const point_t &B,
        const scalar_t &r1,
        const scalar_t &s1,
        const scalar_t &d1,
        std::vector<point_t> L,
        std::vector<point_t> R);

    explicit bulletproof_plus_t(Serialization::deserializer_t &reader);

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
    [[nodiscard]] hash_t hash() const;

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

    /** @brief A: initial vector commitment; A1: WIP auxiliary commitment; B: WIP final commitment. */
    point_t A, A1, B;

    /** @brief Final response scalars from the weighted inner product argument.
     *  r1 and s1 are the folded vector elements; d1 is the blinding response. */
    scalar_t r1, s1, d1;

    /** @brief Left and right commitments from each WIP folding round.
     *  There are log2(N*M) pairs, where N is the bit-length and M is the aggregation count. */
    std::vector<point_t> L, R;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const bulletproof_plus_t &value)
    {
        os << "Bulletproof+ [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.A, "A", 2) << std::endl
           << "\t" << PAD_NAMED(value.A1, "A1", 2) << std::endl
           << "\t" << PAD_NAMED(value.B, "B", 2) << std::endl
           << "\t" << PAD_NAMED(value.r1, "r1", 2) << std::endl
           << "\t" << PAD_NAMED(value.s1, "s1", 2) << std::endl
           << "\t" << PAD_NAMED(value.d1, "d1", 2) << std::endl
           << "\t" << PAD_STR("L", 2) << ":" << std::endl;

        for (const auto &val : value.L)
        {
            os << PAD_STR("\t", 5) << val << std::endl;
        }

        os << "\t" << PAD_STR("R", 2) << ":" << std::endl;

        for (const auto &val : value.R)
        {
            os << PAD_STR("\t", 5) << val << std::endl;
        }

        return os;
    }
} // namespace std

#endif
