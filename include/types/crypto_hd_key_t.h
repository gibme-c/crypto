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

#ifndef CRYPTO_HD_KEY_T_H
#define CRYPTO_HD_KEY_T_H

#include <types/crypto_hash_t.h>
#include <types/crypto_secret_key_t.h>

/**
 * This represents an HD key pair generated from a BIP39 seed
 *
 * Note: This structure is not natively serializable as it should *generally* never
 * be stored anywhere outside of memory and should be re-generated from the seed
 * whenever it is needed
 */
struct crypto_hd_key_t final
{
  public:
    crypto_hd_key_t() = default;

    crypto_hd_key_t(const crypto_hash_t &key, const crypto_hash_t &chain_code);

    [[nodiscard]] crypto_hash_t chain_code() const;

    /**
     * Generates a child key from this HD key
     *
     * Note: These methods assume a fully hardened path, if you need normal path
     * components, please use the generate_child_key(std::string) method
     *
     * @param purpose
     * @param coin_type
     * @param account
     * @param change
     * @param address_index
     * @return
     */
    [[nodiscard]] crypto_hd_key_t
        generate_child_key(size_t purpose, size_t coin_type, size_t account, size_t change, size_t address_index) const;
    [[nodiscard]] crypto_hd_key_t
        generate_child_key(size_t purpose, size_t coin_type, size_t account, size_t change) const;
    [[nodiscard]] crypto_hd_key_t generate_child_key(size_t purpose, size_t coin_type, size_t account) const;
    [[nodiscard]] crypto_hd_key_t generate_child_key(size_t purpose, size_t coin_type) const;
    [[nodiscard]] crypto_hd_key_t generate_child_key(size_t purpose) const;
    [[nodiscard]] crypto_hd_key_t generate_child_key() const;

    /**
     * Generates a child key from this BIP39 seed using the specified path
     *
     * @param path
     * @return
     */
    [[nodiscard]] crypto_hd_key_t generate_child_key(const std::string &path) const;

    [[nodiscard]] crypto_hash_t key() const;

    /**
     * Returns the public and secret keys for this master key
     *
     * @return
     */
    [[nodiscard]] std::tuple<crypto_public_key_t, crypto_secret_key_t> keys() const;

    /**
     * Returns the public key of this master key
     *
     * @return
     */
    [[nodiscard]] crypto_public_key_t public_key() const;

    /**
     * Returns the secret key of this master key
     *
     * @return
     */
    [[nodiscard]] crypto_secret_key_t secret_key() const;

    /**
     * Returns the hex encoded serialized byte array
     * @return
     */
    [[nodiscard]] std::string to_string() const;

  private:
    crypto_hash_t _key, _chain_code;

    crypto_secret_key_t _secret_key;

    crypto_public_key_t _public_key;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_hd_key_t &value)
    {
        os << "Key     : " << value.key() << std::endl
           << "Chain   : " << value.chain_code() << std::endl
           << "\tSecret: " << value.secret_key() << std::endl
           << "\tPublic: " << value.public_key() << std::endl;

        return os;
    }
} // namespace std

#endif
