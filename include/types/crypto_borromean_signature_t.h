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

#ifndef CRYPTO_BORROMEAN_T
#define CRYPTO_BORROMEAN_T

#include <types/crypto_signature_t.h>

struct crypto_borromean_signature_t final : Serializable
{
    crypto_borromean_signature_t() = default;

    crypto_borromean_signature_t(std::initializer_list<unsigned char> input);

    explicit crypto_borromean_signature_t(const std::vector<unsigned char> &input);

    explicit crypto_borromean_signature_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_borromean_signature_t, fromJSON);

    explicit crypto_borromean_signature_t(std::vector<crypto_signature_t> signatures);

    explicit crypto_borromean_signature_t(Serialization::deserializer_t &reader);

    /**
     * Checks that the basic construction of the proof is valid
     * @param ring_size
     * @return
     */
    [[nodiscard]] bool check_construction(size_t ring_size) const;

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(Serialization::deserializer_t &reader) override;

    /**
     * Deserializes the struct from a byte array
     * @param data
     */
    void deserialize(const std::vector<unsigned char> &data) override;

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

    std::vector<crypto_signature_t> signatures;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_borromean_signature_t &value)
    {
        os << "Borromean [" << value.size() << " bytes]: " << value.hash() << std::endl;

        for (const auto &val : value.signatures)
        {
            os << "\t" << val << std::endl;
        }

        return os;
    }
} // namespace std

#endif
