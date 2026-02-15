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

/**
 * @file crypto_hd_key_t.h
 * @brief Hierarchical deterministic (HD) key pairs following BIP-32/BIP-44/SLIP-10.
 *
 * An HD key represents a single node in the key derivation tree. Each key consists of a
 * private key, its corresponding Ed25519 public key, and a chain code that enables further
 * child derivation. The derivation path follows the BIP-44 convention:
 *
 *   m / purpose' / coin_type' / account' / change' / index'
 *
 * All path components are fully hardened (indicated by the apostrophe) as required by SLIP-10
 * for Ed25519 curves -- non-hardened derivation is not possible with Ed25519 because the public
 * key cannot be used to derive child keys without the private key.
 *
 * HD keys are not serializable by design. Regenerate them from a seed whenever needed.
 */

#ifndef CRYPTO_HD_KEY_T_H
#define CRYPTO_HD_KEY_T_H

#include <types/crypto_hash_t.h>
#include <types/crypto_secret_key_t.h>

/**
 * @brief A hierarchical deterministic (HD) key pair -- one node in the BIP-32/SLIP-10 derivation tree.
 *
 * Each HD key holds a private key, the corresponding Ed25519 public key, and a chain code for
 * further child derivation. You typically obtain one from `crypto_seed_t::generate_child_key()`
 * or by calling `generate_child_key()` on an existing HD key to go deeper in the tree.
 *
 * Not serializable by design -- regenerate from a seed whenever you need it.
 */
struct crypto_hd_key_t final
{
  public:
    crypto_hd_key_t() = default;

    /**
     * Constructs an HD key from a raw key and chain code (e.g., from HMAC-SHA512 output).
     *
     * @param key the 32-byte private key material
     * @param chain_code the 32-byte chain code for child derivation
     */
    crypto_hd_key_t(const crypto_hash_t &key, const crypto_hash_t &chain_code);

    /**
     * Returns the chain code for this key, used alongside the private key during child derivation.
     * @return the 32-byte chain code
     */
    [[nodiscard]] crypto_hash_t chain_code() const;

    /**
     * Derives a child HD key using a BIP-44-style path: m/purpose'/coin_type'/account'/change'/index'.
     *
     * All path components are fully hardened per SLIP-10 (required for Ed25519). You can omit
     * trailing components to derive at a higher level -- for example, passing only (purpose, coin_type)
     * derives at m/purpose'/coin_type'.
     *
     * @param purpose the BIP-44 purpose field (e.g., 44)
     * @param coin_type the coin type index
     * @param account the account index
     * @param change the change index (0 = external, 1 = internal)
     * @param address_index the address index within the change chain
     * @return the derived child HD key
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
     * Derives a child HD key using a string path like "m/44'/0'/0'/0/0".
     *
     * Use this when you need a non-standard path depth or want to express the derivation
     * path explicitly. Hardened components are indicated with a trailing apostrophe (').
     *
     * @param path the derivation path string (e.g., "m/44'/0'/0'")
     * @return the derived child HD key
     */
    [[nodiscard]] crypto_hd_key_t generate_child_key(const std::string &path) const;

    /**
     * Returns the raw 32-byte private key material for this node.
     * @return the private key hash
     */
    [[nodiscard]] crypto_hash_t key() const;

    /**
     * Returns both the Ed25519 public key and the secret key as a tuple.
     *
     * This is convenient when you need both at once (e.g., for signing and verification setup).
     *
     * @return a tuple of (public_key, secret_key)
     */
    [[nodiscard]] std::tuple<crypto_public_key_t, crypto_secret_key_t> keys() const;

    /**
     * Returns the Ed25519 public key derived from this HD key's private key material.
     * @return the public key
     */
    [[nodiscard]] crypto_public_key_t public_key() const;

    /**
     * Returns the Ed25519 secret key (RFC-8032 format) derived from this HD key's private key material.
     * @return the secret key
     */
    [[nodiscard]] crypto_secret_key_t secret_key() const;

    /**
     * Returns the key and chain code as a hex-encoded string (for debugging -- handle with care).
     * @return hex string representation
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
