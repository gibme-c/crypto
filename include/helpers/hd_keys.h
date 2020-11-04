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

#ifndef CRYPT_HD_KEYS_H
#define CRYPT_HD_KEYS_H

#include <types/crypto_hash_t.h>

/**
 * Calculates the HMAC SHA-512 using the key and message specified
 *
 * @param key
 * @param key_length
 * @param message
 * @param message_length
 * @return
 */
std::vector<unsigned char>
    calculate_hmac_sha512(const void *key, size_t key_length, const void *message, size_t message_length);

/**
 * Generates an HD child key given the parent key, chain code, and path
 *
 * @param parent_key
 * @param chain_code
 * @param path
 * @return
 */
std::tuple<crypto_hash_t, crypto_hash_t>
    generate_hd_child_key(const crypto_hash_t &parent_key, const crypto_hash_t &chain_code, const std::string &path);

/**
 * Constructs a hardened BIP32 path using the supplied parameters
 *
 * @param purpose
 * @param coin_type
 * @param account
 * @param change
 * @param address_index
 * @return
 */
std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account, size_t change, size_t address_index);
std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account, size_t change);
std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account);
std::string make_bip32_path(size_t purpose, size_t coin_type);
std::string make_bip32_path(size_t purpose);
std::string make_bip32_path();


#endif
