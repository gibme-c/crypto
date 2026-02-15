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
// Based on ePrint 2022/510 (Bulletproofs++)

/**
 * @file crypto_bulletproof_pp_t.h
 * @brief Bulletproofs++ range proof data structure using the reciprocal-argument approach.
 */

#ifndef CRYPTO_BULLETPROOF_PP_T
#define CRYPTO_BULLETPROOF_PP_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * @brief A Bulletproofs++ range proof -- the most compact variant using a reciprocal-argument approach.
 *
 * Bulletproofs++ (ePrint 2022/510) takes a fundamentally different approach from BP and BP+.
 * Instead of an inner product argument, it uses a reciprocal argument combined with a Weighted
 * Norm Linear Argument (WNLA) as the inner proof system. The result is the most compact range
 * proof in this library: approximately 516 bytes for a single 64-bit range proof, compared to
 * ~578 bytes for BP+ and ~674 bytes for original BP.
 *
 * Verification is also faster at around 466 microseconds per proof, with efficient batch
 * verification at roughly 680 microseconds for 8 proofs.
 *
 * This implementation supports single-value proofs only (M=1) with N=64 bits and uses base-16
 * digit decomposition (16 digits of 4 bits each), which provides a good balance between proof
 * size and prover efficiency.
 *
 * Proof components:
 * - C_l, C_r, C_o, C_s: commitment points from the reciprocal-argument encoding
 * - R: the norm argument commitment
 * - X, W: auxiliary points from WNLA folding rounds
 * - l, n: final scalar vectors from the WNLA reduction
 */
struct crypto_bulletproof_pp_t final : Serializable
{
    crypto_bulletproof_pp_t() = default;

    crypto_bulletproof_pp_t(std::initializer_list<unsigned char> input);

    explicit crypto_bulletproof_pp_t(const std::vector<unsigned char> &input);

    explicit crypto_bulletproof_pp_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_bulletproof_pp_t, fromJSON)

    crypto_bulletproof_pp_t(
        const crypto_point_t &C_l,
        const crypto_point_t &C_r,
        const crypto_point_t &C_o,
        const crypto_point_t &C_s,
        const crypto_point_t &R,
        std::vector<crypto_point_t> X,
        std::vector<crypto_point_t> W,
        std::vector<crypto_scalar_t> l,
        std::vector<crypto_scalar_t> n);

    explicit crypto_bulletproof_pp_t(Serialization::deserializer_t &reader);

    /**
     * Checks that the basic construction of the proof is valid.
     *
     * Validates that X and W vectors have matching lengths, l and n have the expected
     * final dimensions, all points are on the curve, and all scalars are reduced. This is
     * a structural check only -- it does not verify the zero-knowledge proof itself.
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

    /** @brief Reciprocal-argument commitment points. C_l and C_r encode the left/right digit
     *  polynomials, C_o encodes the cross-term, and C_s is the shift commitment. */
    crypto_point_t C_l, C_r, C_o, C_s;

    /** @brief Norm argument commitment point from the WNLA initialization. */
    crypto_point_t R;

    /** @brief Auxiliary points from each WNLA folding round. X and W each have one element
     *  per round (typically 4 rounds for N=64, base-16). */
    std::vector<crypto_point_t> X, W;

    /** @brief Final scalar vectors after WNLA reduction. l and n each contain the remaining
     *  unreduced elements (typically 1 element each after all folding rounds). */
    std::vector<crypto_scalar_t> l, n;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_bulletproof_pp_t &value)
    {
        os << "Bulletproof++ [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.C_l, "C_l", 3) << std::endl
           << "\t" << PAD_NAMED(value.C_r, "C_r", 3) << std::endl
           << "\t" << PAD_NAMED(value.C_o, "C_o", 3) << std::endl
           << "\t" << PAD_NAMED(value.C_s, "C_s", 3) << std::endl
           << "\t" << PAD_NAMED(value.R, "R", 3) << std::endl
           << "\t" << PAD_STR("X", 3) << ":" << std::endl;

        for (const auto &val : value.X)
        {
            os << PAD_STR("\t", 6) << val << std::endl;
        }

        os << "\t" << PAD_STR("W", 3) << ":" << std::endl;

        for (const auto &val : value.W)
        {
            os << PAD_STR("\t", 6) << val << std::endl;
        }

        os << "\t" << PAD_STR("l", 3) << ":" << std::endl;

        for (const auto &val : value.l)
        {
            os << PAD_STR("\t", 6) << val << std::endl;
        }

        os << "\t" << PAD_STR("n", 3) << ":" << std::endl;

        for (const auto &val : value.n)
        {
            os << PAD_STR("\t", 6) << val << std::endl;
        }

        return os;
    }
} // namespace std

#endif
