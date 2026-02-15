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

/**
 * @file crypto_seed_t.h
 * @brief BIP-39 seed derived from entropy via PBKDF2, used as the root for HD key derivation.
 *
 * A seed bridges the gap between human-friendly mnemonic entropy and the cryptographic keys
 * your application actually uses. It is produced by running PBKDF2 on the mnemonic phrase with
 * an optional passphrase (which acts as a "25th word" for plausible deniability). From this
 * seed, you can derive an entire tree of hierarchical deterministic (HD) keys.
 *
 * Seeds are intentionally not serializable -- you should regenerate them from entropy when needed
 * rather than persisting them to disk, since they are high-value secret material.
 */

#ifndef CRYPTO_SEED_T_H
#define CRYPTO_SEED_T_H

#include <types/crypto_entropy_t.h>
#include <types/crypto_hash_t.h>
#include <types/crypto_hd_key_t.h>

/**
 * @brief A BIP-39 seed derived from mnemonic entropy via PBKDF2 -- the root of HD key derivation.
 *
 * This is the bridge between human-friendly entropy (mnemonic words) and the cryptographic key
 * tree. Construction runs PBKDF2-SHA512 on the mnemonic with an optional passphrase (acting as
 * a "25th word"), then derives a master key and chain code via HMAC-SHA512 keyed with the
 * @p hmac_key (defaulting to "ed25519 seed" per SLIP-10).
 *
 * Not serializable by design -- regenerate from entropy when needed rather than storing to disk.
 */
struct crypto_seed_t final
{
  public:
    crypto_seed_t() = default;

    ~crypto_seed_t();

    /**
     * Generates a BIP-39 seed from entropy, with an optional passphrase for extra protection.
     *
     * The passphrase acts as a second factor: different passphrases produce entirely different
     * key trees from the same mnemonic, which is useful for plausible deniability. The hmac_key
     * selects which curve's derivation scheme to use (e.g., "ed25519 seed" for SLIP-10 Ed25519).
     *
     * @param entropy the BIP-39 entropy to derive the seed from
     * @param passphrase optional passphrase ("25th word") mixed into PBKDF2
     * @param hmac_key the HMAC key for root key derivation (defaults to "ed25519 seed")
     */
    explicit crypto_seed_t(
        const crypto_entropy_t &entropy,
        const std::string &passphrase = "",
        const std::string &hmac_key = "ed25519 seed");

    /**
     * Constructs a seed directly from raw bytes (e.g., if you already have 64 bytes of seed material).
     *
     * @param raw_seed the raw seed bytes (typically 64 bytes from PBKDF2)
     * @param hmac_key the HMAC key for root key derivation (defaults to "ed25519 seed")
     */
    explicit crypto_seed_t(const std::vector<unsigned char> &raw_seed, const std::string &hmac_key = "ed25519 seed");

    /**
     * Returns the master chain code, which is used alongside the master key during child key
     * derivation to ensure that sibling keys are cryptographically independent.
     *
     * @return the 32-byte master chain code
     */
    [[nodiscard]] crypto_hash_t chain_code() const;

    /**
     * Derives a child HD key using a BIP-44-style path: m/purpose'/coin_type'/account'/change'/index'.
     *
     * All path components are fully hardened per SLIP-10 (required for Ed25519 compatibility).
     * You can omit trailing components to derive at a higher level in the tree -- for example,
     * passing only (purpose, coin_type) derives at m/purpose'/coin_type'.
     *
     * @param purpose the BIP-44 purpose field (e.g., 44)
     * @param coin_type the coin type index
     * @param account the account index
     * @param change the change index (0 = external, 1 = internal)
     * @param address_index the address index within the change chain
     * @return the derived HD key at the specified path depth
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
     * @return the derived HD key at the specified path
     */
    [[nodiscard]] crypto_hd_key_t generate_child_key(const std::string &path) const;

    /**
     * Returns the master private key derived from the seed via HMAC-SHA512.
     *
     * @return the 32-byte master key
     */
    [[nodiscard]] crypto_hash_t key() const;

    /**
     * Returns the seed as a hex-encoded string (for debugging -- handle with care).
     *
     * @return hex string representation of the raw seed bytes
     */
    [[nodiscard]] std::string to_string() const;

  private:
    crypto_hash_t _key, _chain_code;

    std::vector<unsigned char> bytes;

    /**
     * Derives the master key and chain code from the raw seed bytes via HMAC-SHA512.
     *
     * @param hmac_key the HMAC key (e.g., "ed25519 seed")
     */
    void generate_root_key(const std::string &hmac_key);

    /**
     * Runs PBKDF2-SHA512 on the mnemonic phrase (derived from entropy) and passphrase to
     * produce the raw 64-byte BIP-39 seed material.
     *
     * @param entropy the BIP-39 entropy to derive the mnemonic from
     * @param passphrase the optional passphrase mixed into PBKDF2
     */
    void calculate_bip39(const crypto_entropy_t &entropy, const std::string &passphrase = "");
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_seed_t &value)
    {
        os << value.to_string();

        return os;
    }
} // namespace std

#endif
