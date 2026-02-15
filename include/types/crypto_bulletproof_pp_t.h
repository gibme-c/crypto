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

#ifndef CRYPTO_BULLETPROOF_PP_T
#define CRYPTO_BULLETPROOF_PP_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * A Bulletproof++ Range Proof
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
     * Checks that the basic construction of the proof is valid
     * @return
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
     * @return
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
     * Returns the serialized byte size
     * @return
     */
    [[nodiscard]] size_t size() const override;

    /**
     * Writes the structure as JSON to the provided writer
     * @param writer
     */
    JSON_TO_FUNC(toJSON) override;

    /**
     * Returns the hex encoded serialized byte array
     * @return
     */
    [[nodiscard]] std::string to_string() const override;

    crypto_point_t C_l, C_r, C_o, C_s;
    crypto_point_t R;
    std::vector<crypto_point_t> X, W;
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
