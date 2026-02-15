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
 * @file hd_keys.h
 * @brief HMAC-SHA512 and BIP-32/BIP-44 path helpers for hierarchical deterministic key derivation.
 *
 * Hierarchical deterministic (HD) keys let you derive an entire tree of key pairs from
 * a single master seed. This module provides the low-level HMAC-SHA512 primitive and
 * the child key derivation function used by SLIP-0010 (Ed25519 variant of BIP-32),
 * plus helper functions for constructing standard BIP-44 derivation paths like
 * `m/44'/0'/0'/0/0` (all hardened).
 */

#ifndef CRYPT_HD_KEYS_H
#define CRYPT_HD_KEYS_H

#include <types/crypto_hash_t.h>

/**
 * Computes HMAC-SHA512 over the given message with the given key.
 *
 * This is the core building block for BIP-32 key derivation: each child key
 * is derived by HMAC-SHA512(parent_chain_code, parent_key || index).
 *
 * @param key pointer to the HMAC key bytes
 * @param key_length length of the key in bytes
 * @param message pointer to the message bytes
 * @param message_length length of the message in bytes
 * @return the 64-byte HMAC-SHA512 result
 */
std::vector<unsigned char>
    calculate_hmac_sha512(const void *key, size_t key_length, const void *message, size_t message_length);

/**
 * Derives an HD child key from a parent key and chain code along the given path.
 *
 * Walks each segment of the BIP-32 path (e.g., "m/44'/0'/0'") applying hardened
 * child derivation at each step via HMAC-SHA512.
 *
 * @param parent_key the 32-byte parent private key
 * @param chain_code the 32-byte parent chain code
 * @param path the BIP-32 derivation path string (e.g., "m/44'/0'/0'")
 * @return a tuple of {child_key, child_chain_code}
 */
std::tuple<crypto_hash_t, crypto_hash_t>
    generate_hd_child_key(const crypto_hash_t &parent_key, const crypto_hash_t &chain_code, const std::string &path);

/**
 * Constructs a fully-hardened BIP-44 derivation path string: `m/purpose'/coin'/account'/change'/index'`.
 *
 * Overloads with fewer parameters produce shorter paths (e.g., just `m/purpose'`).
 *
 * @param purpose the BIP-44 purpose field (typically 44)
 * @param coin_type the coin type identifier
 * @param account the account index
 * @param change the change flag (0 = external, 1 = internal)
 * @param address_index the address index within the account
 * @return the path string (e.g., "m/44'/0'/0'/0'/0'")
 */
std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account, size_t change, size_t address_index);
std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account, size_t change);
std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account);
std::string make_bip32_path(size_t purpose, size_t coin_type);
std::string make_bip32_path(size_t purpose);
std::string make_bip32_path();


#endif
