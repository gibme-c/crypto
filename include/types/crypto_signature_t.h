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

#ifndef CRYPTO_SIGNATURE_T
#define CRYPTO_SIGNATURE_T

#include <types/crypto_hash_t.h>
#include <types/crypto_scalar_t.h>

struct crypto_signature_t final : Serializable
{
    /**
     * Constructor methods
     */

    crypto_signature_t() = default;

    crypto_signature_t(std::initializer_list<unsigned char> LR);

    explicit crypto_signature_t(const std::vector<unsigned char> &LR);

    explicit crypto_signature_t(const std::string &LR);

    JSON_STRING_CONSTRUCTOR(crypto_signature_t, fromJSON)

    /**
     * Simple operator overloads for comparison
     */

    bool operator==(const crypto_signature_t &other) const;

    bool operator!=(const crypto_signature_t &other) const;

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
     * Returns if the structure is empty (unset)
     * @return
     */
    [[nodiscard]] bool empty() const;

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
     * @param writer
     */
    void serialize(Serialization::serializer_t &writer) const override;

    /**
     * Serializes the struct to a byte array
     * @return
     */
    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    /**
     * Use this method instead of sizeof(crypto_signature_t) to get the resulting size of the value in bytes
     * @return
     */
    [[nodiscard]] size_t size() const override;

    /**
     * Converts the structure to a JSON object
     * @param writer
     */
    JSON_TO_FUNC(toJSON) override;

    /**
     * Encodes a signature as a hexadecimal string
     * @return
     */
    [[nodiscard]] std::string to_string() const override;

  private:
    /**
     * Loads a signature from a hexademical string
     * @param s
     */
    void from_string(const std::string &s);

    /**
     * A signature is composes of two scalars concatenated together such that S = (L || R)
     */
    struct signature_scalars
    {
        crypto_scalar_t L;
        crypto_scalar_t R;
    };

  public:
    /**
     * Provides an easy to reference structure for the signature of either the concatenated
     * L and R values together as a single 64 bytes or via the individual L & R scalars
     */
    signature_scalars LR;
};

/**
 * Providing overloads into the std namespace such that we can easily included
 * points, scalars, and signatures in output streams
 */
namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_signature_t &value)
    {
        os << value.to_string();

        return os;
    }
} // namespace std

#endif
