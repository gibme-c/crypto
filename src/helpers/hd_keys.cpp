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

#include <cryptopp/hmac.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <helpers/hd_keys.h>

static std::vector<uint32_t> parse_bip32_path(const std::string &path)
{
    if (path.empty() || path[0] != 'm')
    {
        throw std::invalid_argument("Invalid BIP-32 path: must start with m");
    }

    std::vector<uint32_t> indices;

    if (path.size() > 2)
    {
        std::istringstream stream(path.substr(2)); // skip m

        std::string segment;

        while (std::getline(stream, segment, '/'))
        {
            if (segment.empty())
            {
                throw std::invalid_argument("Invalid BIP-32 path: empty segment");
            }

            bool hardened = segment.back() == '\'';

            if (hardened)
            {
                segment.pop_back();
            }

            auto index = std::stoul(segment);

            if (hardened)
            {
                index += 0x80000000; // Add hardened bit
            }

            indices.push_back(index);
        }
    }

    return indices;
}

static std::tuple<crypto_hash_t, crypto_hash_t>
    generate_hd_child_key(const crypto_hash_t &parent_key, const crypto_hash_t &chain_code, size_t index)
{
    CryptoPP::byte data[37];

    crypto_hash_t child_key, child_chain_code;

    data[0] = 0x00;

    std::copy(parent_key.data(), parent_key.data() + parent_key.size(), data + 1);

    data[33] = (index >> 24) & 0xFF;

    data[34] = (index >> 16) & 0xFF;

    data[35] = (index >> 8) & 0xFF;

    data[36] = index & 0xFF;

    const auto hash = calculate_hmac_sha512(chain_code.data(), chain_code.size(), data, sizeof(data));

    std::vector<unsigned char> temp;

    temp.assign(hash.begin(), hash.begin() + 32);

    child_key.deserialize(temp);

    temp.assign(hash.begin() + 32, hash.begin() + 64);

    child_chain_code.deserialize(temp);

    return {child_key, child_chain_code};
}

std::vector<unsigned char>
    calculate_hmac_sha512(const void *key, size_t key_length, const void *message, size_t message_length)
{
    std::vector<unsigned char> result(CryptoPP::HMAC<CryptoPP::SHA512>::DIGESTSIZE);

    const auto hmac_context =
        new CryptoPP::HMAC<CryptoPP::SHA512>(static_cast<const CryptoPP::byte *>(key), key_length);

    hmac_context->Update(static_cast<const CryptoPP::byte *>(message), message_length);

    hmac_context->Final(result.data());

    free(hmac_context);

    return result;
}

std::tuple<crypto_hash_t, crypto_hash_t>
    generate_hd_child_key(const crypto_hash_t &parent_key, const crypto_hash_t &chain_code, const std::string &path)
{
    crypto_hash_t current_key = parent_key;

    crypto_hash_t current_chain_code = chain_code;

    const auto indices = parse_bip32_path(path);

    for (const auto index : indices)
    {
        const auto [child_key, child_chain_code] = generate_hd_child_key(current_key, current_chain_code, index);

        current_key = child_key;

        current_chain_code = child_chain_code;
    }

    return {current_key, current_chain_code};
}


std::string make_bip32_path(
    const size_t purpose,
    const size_t coin_type,
    const size_t account,
    const size_t change,
    const size_t address_index)
{
    return "m/" + std::to_string(purpose) + "'/" + std::to_string(coin_type) + "'/" + std::to_string(account) + "'/"
           + std::to_string(change) + "'/" + std::to_string(address_index) + "'";
}

std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account, size_t change)
{
    return "m/" + std::to_string(purpose) + "'/" + std::to_string(coin_type) + "'/" + std::to_string(account) + "'/"
           + std::to_string(change) + "'";
}

std::string make_bip32_path(size_t purpose, size_t coin_type, size_t account)
{
    return "m/" + std::to_string(purpose) + "'/" + std::to_string(coin_type) + "'/" + std::to_string(account) + "'";
}

std::string make_bip32_path(size_t purpose, size_t coin_type)
{
    return "m/" + std::to_string(purpose) + "'/" + std::to_string(coin_type) + "'";
}

std::string make_bip32_path(size_t purpose)
{
    return "m/" + std::to_string(purpose) + "'";
}

std::string make_bip32_path()
{
    return "m";
}
