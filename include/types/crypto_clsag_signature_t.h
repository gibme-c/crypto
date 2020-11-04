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
// Inspired by the work of Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/clsag

#ifndef CRYPTO_CLSAG_T
#define CRYPTO_CLSAG_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

struct crypto_clsag_signature_t final : Serializable
{
    crypto_clsag_signature_t() = default;

    crypto_clsag_signature_t(std::initializer_list<unsigned char> input);

    explicit crypto_clsag_signature_t(const std::vector<unsigned char> &input);

    explicit crypto_clsag_signature_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_clsag_signature_t, fromJSON);

    crypto_clsag_signature_t(
        std::vector<crypto_scalar_t> scalars,
        const crypto_scalar_t &challenge,
        const crypto_key_image_t &commitment_image = Crypto::Z,
        const crypto_pedersen_commitment_t &pseudo_commitment = Crypto::Z);

    explicit crypto_clsag_signature_t(Serialization::deserializer_t &reader);

    /**
     * Checks that the basic construction of the proof is valid
     * @param ring_size
     * @return
     */
    [[nodiscard]] bool check_construction(size_t ring_size, bool use_commitments = false) const;

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
    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    /**
     * Returns the hex encoded serialized byte array
     * @return
     */
    [[nodiscard]] std::string to_string() const override;

    std::vector<crypto_scalar_t> scalars;
    crypto_key_image_t commitment_image;
    crypto_scalar_t challenge;
    crypto_pedersen_commitment_t pseudo_commitment;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_clsag_signature_t &value)
    {
        os << "CLSAG [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_STR("scalars", 17) << ":" << std::endl;

        for (const auto &val : value.scalars)
        {
            os << PAD_STR("\t", 20) << val << std::endl;
        }

        os << "\t" << PAD_NAMED(value.challenge, "challenge", 17) << std::endl;

        if (value.commitment_image.valid())
        {
            os << "\t" << PAD_NAMED(value.commitment_image, "commitment_image", 17) << std::endl
               << "\t" << PAD_NAMED(value.pseudo_commitment, "pseudo_commitment", 17) << std::endl;
        }

        return os;
    }
} // namespace std

#endif
