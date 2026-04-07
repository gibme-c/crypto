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
 * @file entropy_t.cpp
 * @brief BIP-39 entropy: random generation with optional timestamp prefix, mnemonic encoding/decoding.
 */

#include <chrono>
#include <core/crypto_config.h>
#include <core/crypto_constants.h>
#include <mnemonics/mnemonics.h>
#include <types/entropy_t.h>
#include <types/hash_t.h>

static uint64_t now()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();

    return std::chrono::duration_cast<std::chrono::seconds>(now).count();
}

entropy_t::entropy_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));
}

entropy_t::entropy_t(const std::vector<unsigned char> &input)
{
    if (input.size() > sizeof(bytes))
    {
        throw std::runtime_error("Could not load entropy");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));
}

entropy_t::entropy_t(const std::string &s)
{
    from_string(s);
}

entropy_t entropy_t::random(const size_t bits, const std::vector<unsigned char> &entropy, const bool encode_timestamp)
{
    if (bits != 256 && bits != 128)
    {
        throw std::invalid_argument("seed must be 128 or 256 bits");
    }

    entropy_t seed;

    // Start with OS-sourced random bytes
    auto hash = hash_t::random();

    Serialization::serializer_t writer;

    // Mix in caller-supplied entropy if provided
    if (!entropy.empty())
    {
        writer.pod(hash);

        writer.bytes(entropy);

        hash = hash_t::sha3(writer.vector());
    }

    // Build the entropy payload: optional varint timestamp prefix followed by random bytes
    writer.reset();
    {
        if (encode_timestamp)
        {
            writer.varint(now());
        }

        writer.bytes(hash.data(), seed.size() - writer.size());
    }

    auto temp = writer.vector();

    // For 128-bit entropy, zero out the upper 16 bytes
    if (bits == 128)
    {
        temp.resize(16);

        temp.resize(32);
    }

    seed.deserialize(temp);

    return seed;
}

entropy_t
    entropy_t::recover(const std::vector<std::string> &words, const Crypto::Mnemonics::Language::Language &language)
{
    entropy_t seed;

    const auto bytes = Crypto::Mnemonics::decode_raw(words, language);

    seed.deserialize(bytes);

    return seed;
}

entropy_t entropy_t::recover(const std::string &phrase, const Crypto::Mnemonics::Language::Language &language)
{
    const auto words = Serialization::str_split(phrase);

    return recover(words, language);
}

void entropy_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.String(Serialization::to_hex(bytes, sizeof(bytes)));
}

// Attempts to decode a varint timestamp from the start of the entropy.
// Returns 0 if the decoded value falls outside the valid timestamp window,
// indicating no timestamp was encoded (or it is not recoverable).
uint64_t entropy_t::timestamp() const
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

std::string entropy_t::to_mnemonic_phrase(const Crypto::Mnemonics::Language::Language &language) const
{
    const auto words = to_mnemonic_words(language);

    return Serialization::str_join(words);
}

std::vector<std::string> entropy_t::to_mnemonic_words(const Crypto::Mnemonics::Language::Language &language) const
{
    auto temp = std::vector<unsigned char>(std::begin(bytes), std::end(bytes));

    if (is_128_bit())
    {
        temp.resize(16);
    }

    return Crypto::Mnemonics::encode(temp, language);
}

std::string entropy_t::to_string() const
{
    if (is_128_bit())
    {
        return Serialization::to_hex(std::begin(bytes), 16);
    }

    return Serialization::to_hex(std::begin(bytes), 32);
}


// 128-bit entropy is stored in the lower 16 bytes with the upper 16 bytes zeroed
bool entropy_t::is_128_bit() const
{
    return std::all_of(std::end(bytes) - 16, std::end(bytes), [](unsigned char byte) { return byte == 0; });
}
