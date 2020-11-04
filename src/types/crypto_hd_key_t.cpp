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

#include <cryptopp/sha.h>
#include <helpers/hd_keys.h>
#include <types/crypto_hd_key_t.h>

crypto_hd_key_t::crypto_hd_key_t(const crypto_hash_t &key, const crypto_hash_t &chain_code)
{
    _key = key;

    _chain_code = chain_code;

    _secret_key = crypto_secret_key_t(_key.serialize());

    _public_key = _secret_key.point();
}

crypto_hash_t crypto_hd_key_t::chain_code() const
{
    return _chain_code;
}

crypto_hd_key_t crypto_hd_key_t::generate_child_key(
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

crypto_hd_key_t crypto_hd_key_t::generate_child_key(
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
    crypto_hd_key_t::generate_child_key(const size_t purpose, const size_t coin_type, const size_t account) const
{
    const std::string path = make_bip32_path(purpose, coin_type, account);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_hd_key_t::generate_child_key(const size_t purpose, const size_t coin_type) const
{
    const std::string path = make_bip32_path(purpose, coin_type);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_hd_key_t::generate_child_key(const size_t purpose) const
{
    const std::string path = make_bip32_path(purpose);

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hd_key_t crypto_hd_key_t::generate_child_key() const
{
    const std::string path = make_bip32_path();

    const auto [child_key, child_chain_code] = generate_hd_child_key(_key, _chain_code, path);

    return crypto_hd_key_t(child_key, child_chain_code);
}

crypto_hash_t crypto_hd_key_t::key() const
{
    return _key;
}

std::tuple<crypto_public_key_t, crypto_secret_key_t> crypto_hd_key_t::keys() const
{
    return {_public_key, _secret_key};
}

crypto_public_key_t crypto_hd_key_t::public_key() const
{
    return _public_key;
}

crypto_secret_key_t crypto_hd_key_t::secret_key() const
{
    return _secret_key;
}

std::string crypto_hd_key_t::to_string() const
{
    return _key.to_string() + _chain_code.to_string();
}
