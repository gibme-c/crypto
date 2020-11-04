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
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

#ifndef CRYPTO_TRIPTYCH_T
#define CRYPTO_TRIPTYCH_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

struct crypto_triptych_signature_t final : Serializable
{
    crypto_triptych_signature_t() = default;

    crypto_triptych_signature_t(std::initializer_list<unsigned char> input);

    explicit crypto_triptych_signature_t(const std::vector<unsigned char> &input);

    explicit crypto_triptych_signature_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_triptych_signature_t, fromJSON)

    crypto_triptych_signature_t(
        const crypto_key_image_t &commitment_image,
        const crypto_pedersen_commitment_t &pseudo_commitment,
        const crypto_point_t &A,
        const crypto_point_t &B,
        const crypto_point_t &C,
        const crypto_point_t &D,
        std::vector<crypto_point_t> X,
        std::vector<crypto_point_t> Y,
        std::vector<std::vector<crypto_scalar_t>> f,
        const crypto_scalar_t &zA,
        const crypto_scalar_t &zC,
        const crypto_scalar_t &z);

    explicit crypto_triptych_signature_t(Serialization::deserializer_t &reader);

    /**
     * Checks that the basic construction of the proof is valid
     * @param m
     * @param n
     * @return
     */
    [[nodiscard]] bool check_construction(size_t m, size_t n = 2) const;

    void deserialize(const std::vector<unsigned char> &data) override;

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(Serialization::deserializer_t &reader) override;

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
     * Provides the hash of the serialized structure
     * @return
     */
    [[nodiscard]] crypto_hash_t hash() const;

    /**
     * Serializes the struct to a byte array
     * @return
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

    crypto_key_image_t commitment_image;
    crypto_pedersen_commitment_t pseudo_commitment;
    crypto_point_t A, B, C, D;
    std::vector<crypto_point_t> X, Y;
    std::vector<std::vector<crypto_scalar_t>> f;
    crypto_scalar_t zA, zC, z;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_triptych_signature_t &value)
    {
        os << "Triptych [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.A, "A", 17) << std::endl
           << "\t" << PAD_NAMED(value.B, "B", 17) << std::endl
           << "\t" << PAD_NAMED(value.C, "C", 17) << std::endl
           << "\t" << PAD_NAMED(value.D, "D", 17) << std::endl
           << "\t" << PAD_STR("X", 17) << ":" << std::endl;

        for (const auto &val : value.X)
        {
            os << PAD_STR("\t", 20) << val << std::endl;
        }
        os << std::endl;

        os << "\t" << PAD_STR("Y", 17) << ":" << std::endl;

        for (const auto &val : value.Y)
        {
            os << PAD_STR("\t", 20) << val << std::endl;
        }
        os << std::endl;

        os << "\t" << PAD_STR("f", 17) << ":" << std::endl;
        for (const auto &level1 : value.f)
        {
            for (const auto &val : level1)
            {
                os << PAD_STR("\t", 20) << val << std::endl;
            }

            os << std::endl;
        }
        os << std::endl;

        os << "\t" << PAD_NAMED(value.zA, "zA", 17) << std::endl
           << "\t" << PAD_NAMED(value.zC, "zC", 17) << std::endl
           << "\t" << PAD_NAMED(value.z, "z", 17) << std::endl
           << "\t" << PAD_NAMED(value.commitment_image, "commitment_image", 17) << std::endl
           << "\t" << PAD_NAMED(value.pseudo_commitment, "pseudo_commitment", 17) << std::endl;

        return os;
    }
} // namespace std

#endif
