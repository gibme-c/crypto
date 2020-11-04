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
// https://github.com/SarangNoether/skunkworks/tree/pybullet-plus

#ifndef CRYPTO_BULLETPROOF_PLUS_T
#define CRYPTO_BULLETPROOF_PLUS_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * A Bulletproof+ Range Proof
 */
struct crypto_bulletproof_plus_t final : Serializable
{
    crypto_bulletproof_plus_t() = default;

    crypto_bulletproof_plus_t(std::initializer_list<unsigned char> input);

    explicit crypto_bulletproof_plus_t(const std::vector<unsigned char> &input);

    explicit crypto_bulletproof_plus_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_bulletproof_plus_t, fromJSON)

    crypto_bulletproof_plus_t(
        const crypto_point_t &A,
        const crypto_point_t &A1,
        const crypto_point_t &B,
        const crypto_scalar_t &r1,
        const crypto_scalar_t &s1,
        const crypto_scalar_t &d1,
        std::vector<crypto_point_t> L,
        std::vector<crypto_point_t> R);

    explicit crypto_bulletproof_plus_t(Serialization::deserializer_t &reader);

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

    crypto_point_t A, A1, B;
    crypto_scalar_t r1, s1, d1;
    std::vector<crypto_point_t> L, R;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_bulletproof_plus_t &value)
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
