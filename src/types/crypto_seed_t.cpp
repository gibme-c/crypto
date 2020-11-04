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

#include <chrono>
#include <crypto_config.h>
#include <crypto_constants.h>
#include <encoding/mnemonics.h>
#include <types/crypto_hash_t.h>
#include <types/crypto_seed_t.h>

static inline uint64_t now()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();

    return std::chrono::duration_cast<std::chrono::seconds>(now).count();
}

crypto_seed_t::crypto_seed_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));
}

crypto_seed_t::crypto_seed_t(const std::vector<unsigned char> &input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));
}

crypto_seed_t::crypto_seed_t(const std::string &s)
{
    from_string(s);
}

crypto_seed_t crypto_seed_t::random(size_t bits)
{
    return random({}, bits);
}

crypto_seed_t crypto_seed_t::random(const std::vector<unsigned char> &entropy, size_t bits)
{
    if (bits != 256 && bits != 128)
    {
        throw std::invalid_argument("seed must be 128 or 256 bits");
    }

    crypto_seed_t seed;

    Serialization::serializer_t writer;

    writer.pod(crypto_hash_t::random());

    if (!entropy.empty())
    {
        writer.bytes(entropy);
    }

    const auto hash = crypto_hash_t::sha3_slow(writer.data(), writer.size(), CRYPTO_SEED_GENERATION_ITERATIONS);

    writer.reset();

    {
        writer.varint(now());

        writer.bytes(hash.data(), seed.size() - writer.size());
    }

    auto temp = writer.vector();

    if (bits == 128)
    {
        temp.resize(16);

        temp.resize(32);
    }

    seed.deserialize(temp);

    return seed;
}

crypto_seed_t
    crypto_seed_t::recover(const std::vector<std::string> &words, const Crypto::Mnemonics::Language::Language &language)
{
    crypto_seed_t seed;

    const auto bytes = Crypto::Mnemonics::decode_raw(words, language);

    seed.deserialize(bytes);

    return seed;
}

crypto_seed_t crypto_seed_t::recover(const std::string &phrase, const Crypto::Mnemonics::Language::Language &language)
{
    const auto words = Serialization::str_split(phrase);

    return recover(words, language);
}

std::tuple<crypto_public_key_t, crypto_secret_key_t> crypto_seed_t::spend_keys(uint64_t wallet_index) const
{
    auto writer = Serialization::serializer_t();

    writer.pod(SPEND_KEY_DOMAIN_0);

    writer.pod(*this);

    writer.uint64(wallet_index);

    const auto secret_key = crypto_hash_t::sha3(writer).scalar();

    // A = (a * G) mod l
    return {secret_key * Crypto::G, secret_key};
}

uint64_t crypto_seed_t::timestamp() const
{
    try
    {
        const auto ts = Serialization::deserializer_t(serialize()).varint<uint64_t>();

        if (ts >= CRYPTO_MINIMUM_SEED_TIMESTAMP && ts <= CRYPTO_MAXIMUM_SEED_TIMESTAMP)
        {
            return ts;
        }

        return 0;
    }
    catch (const std::exception &)
    {
        return 0;
    }
}

std::string crypto_seed_t::to_mnemonic_phrase(const Crypto::Mnemonics::Language::Language &language) const
{
    const auto words = to_mnemonic_words(language);

    return Serialization::str_join(words);
}

std::vector<std::string> crypto_seed_t::to_mnemonic_words(const Crypto::Mnemonics::Language::Language &language) const
{
    auto temp = std::vector<unsigned char>(std::begin(bytes), std::end(bytes));

    if (is_128_bit())
    {
        temp.resize(16);
    }

    return Crypto::Mnemonics::encode(temp, language);
}

std::tuple<crypto_public_key_t, crypto_secret_key_t> crypto_seed_t::view_keys() const
{
    auto writer = Serialization::serializer_t();

    writer.pod(VIEW_KEY_DOMAIN_0);

    writer.pod(*this);

    const auto secret_key = crypto_hash_t::sha3(writer).scalar();

    // A = (a * G) mod l
    return {secret_key * Crypto::G, secret_key};
}

bool crypto_seed_t::is_128_bit() const
{
    return std::all_of(std::end(bytes) - 16, std::end(bytes), [](unsigned char byte) { return byte == 0; });
}
