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
 * @file crypto_seed_t.cpp
 * @brief BIP-39 seed derivation via PBKDF2-SHA512 (2048 rounds) and SLIP-10 HD root/child key generation.
 */

#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <ed25519/include/ed25519_secure_erase.h>
#include <helpers/hd_keys.h>
#include <types/crypto_seed_t.h>

// BIP-39 key stretching: PBKDF2-HMAC-SHA512 with 2048 iterations, producing a 64-byte seed.
static std::vector<unsigned char>
    calculate_bip39_raw(const void *raw_bytes, size_t raw_bytes_length, const std::string &salt)
{
    std::vector<unsigned char> bytes(64);

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2_context;

    pbkdf2_context.DeriveKey(
        bytes.data(),
        bytes.size(),
        0,
        static_cast<const CryptoPP::byte *>(raw_bytes),
        raw_bytes_length,
        static_cast<const CryptoPP::byte *>((void *)salt.data()),
        salt.size(),
        2048);

    return bytes;
}

crypto_seed_t::crypto_seed_t(
    const crypto_entropy_t &entropy,
    const std::string &passphrase,
    const std::string &hmac_key)
{
    calculate_bip39(entropy, passphrase);

    generate_root_key(hmac_key);
}

crypto_seed_t::crypto_seed_t(const std::vector<unsigned char> &raw_seed, const std::string &hmac_key)
{
    bytes = raw_seed;

    generate_root_key(hmac_key);
}

crypto_seed_t::~crypto_seed_t()
{
    ed25519_secure_erase(bytes.data(), bytes.size());

    ed25519_secure_erase(*_key, _key.size());

    ed25519_secure_erase(*_chain_code, _chain_code.size());
}

crypto_hd_key_t crypto_seed_t::generate_child_key(
    const size_t purpose,
    const size_t coin_type,
    const size_t account,
    const size_t change,
    const size_t address_index) const
{
    const std::string path = make_bip32_path(purpose, coin_type, account, change, address_index);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_seed_t::generate_child_key(
    const size_t purpose,
    const size_t coin_type,
    const size_t account,
    const size_t change) const
{
    const std::string path = make_bip32_path(purpose, coin_type, account, change);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t
    crypto_seed_t::generate_child_key(const size_t purpose, const size_t coin_type, const size_t account) const
{
    const std::string path = make_bip32_path(purpose, coin_type, account);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_seed_t::generate_child_key(const size_t purpose, const size_t coin_type) const
{
    const std::string path = make_bip32_path(purpose, coin_type);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_seed_t::generate_child_key(const size_t purpose) const
{
    const std::string path = make_bip32_path(purpose);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_seed_t::generate_child_key() const
{
    const std::string path = make_bip32_path();

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_seed_t::generate_child_key(const std::string &path) const
{
    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

// SLIP-10: derive root key and chain code from the 64-byte seed via HMAC-SHA512.
// The left 32 bytes become the root private key; the right 32 bytes become the chain code.
void crypto_seed_t::generate_root_key(const std::string &hmac_key)
{
    const auto hash = calculate_hmac_sha512(hmac_key.data(), hmac_key.size(), bytes.data(), bytes.size());

    std::vector<unsigned char> temp;

    temp.assign(hash.begin(), hash.begin() + 32);

    _key.deserialize(temp);

    temp.assign(hash.begin() + 32, hash.end());

    _chain_code.deserialize(temp);

    ed25519_secure_erase(temp.data(), temp.size());
}

// Converts entropy to a mnemonic phrase, then derives the 64-byte BIP-39 seed.
// Sensitive intermediates (mnemonic string and raw seed) are securely erased.
void crypto_seed_t::calculate_bip39(const crypto_entropy_t &entropy, const std::string &passphrase)
{
    auto mnemonic = entropy.to_mnemonic_phrase();

    auto bip39 = calculate_bip39_raw(mnemonic.data(), mnemonic.size(), "mnemonic" + passphrase);

    bytes.resize(bip39.size());

    std::copy(bip39.begin(), bip39.end(), bytes.data());

    ed25519_secure_erase(bip39.data(), bip39.size());

    ed25519_secure_erase(&mnemonic[0], mnemonic.size());
}

crypto_hash_t crypto_seed_t::chain_code() const
{
    return _chain_code;
}

crypto_hash_t crypto_seed_t::key() const
{
    return _key;
}

std::string crypto_seed_t::to_string() const
{
    return Serialization::to_hex(bytes.data(), bytes.size());
}
