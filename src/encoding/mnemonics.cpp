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

#include <bitset>
#include <encoding/mnemonics.h>
#include <helpers/debug_helper.h>
#include <map>
#include <serialization.h>
#include <types/crypto_hash_t.h>

static std::map<Crypto::Mnemonics::Language::Language, std::vector<std::string>> cached_trimmed_words =
    std::map<Crypto::Mnemonics::Language::Language, std::vector<std::string>>();

static inline std::string utf8_substr(const std::string &str, size_t length)
{
    if (length == 0)
    {
        return "";
    }

    size_t min = std::string::npos, max = std::string::npos;

    unsigned int c, i, ix, q;

    for (q = 0, i = 0, ix = str.length(); i < ix; i++, q++)
    {
        if (q == 0)
        {
            min = i;
        }

        if (q <= 0 + length || length == std::string::npos)
        {
            max = i;
        }

        c = static_cast<unsigned char>(str[i]);

        if (c <= 127)
        {
            i += 0;
        }
        else if ((c & 0xE0) == 0xC0)
        {
            i += 1;
        }
        else if ((c & 0xF0) == 0xE0)
        {
            i += 2;
        }
        else if ((c & 0xF8) == 0xF0)
        {
            i += 3;
        }
        // else if (($c & 0xFC) == 0xF8) i+=4; // 111110bb //byte 5, unnecessary in 4 byte UTF-8
        // else if (($c & 0xFE) == 0xFC) i+=5; // 1111110b //byte 6, unnecessary in 4 byte UTF-8
        else
            return ""; // invalid utf8
    }

    if (q <= length || length == std::string::npos)
    {
        max = i;
    }

    if (min == std::string::npos || max == std::string::npos)
    {
        return "";
    }

    return str.substr(min, max);
}

namespace Crypto::Mnemonics
{
    crypto_entropy_t decode(const std::vector<std::string> &words, const Language::Language &language)
    {
        const auto result = decode_raw(words, language);

        Serialization::deserializer_t reader(result);

        return reader.pod<crypto_entropy_t>();
    }

    std::vector<unsigned char> decode_raw(const std::vector<std::string> &words, const Language::Language &language)
    {
        if (words.size() != 24 && words.size() != 12)
        {
            throw std::invalid_argument("Mnemonic must contain exactly 24 words");
        }

        std::string binary_string;

        for (const std::string &word : words)
        {
            const auto index = word_index(word, language);

            if (index == -1)
            {
                throw std::invalid_argument("Invalid word in mnemonic");
            }

            binary_string += std::bitset<11>(index).to_string();
        }

        const auto entropy_size = words.size() == 24 ? 32 : 16;

        size_t entropy_length = entropy_size * 8;

        const auto entropy_bits = binary_string.substr(0, entropy_length);

        const auto checksum_bits = binary_string.substr(entropy_length);

        std::vector<unsigned char> entropy(entropy_size);

        for (size_t i = 0; i < entropy.size(); ++i)
        {
            entropy[i] = static_cast<unsigned char>(std::bitset<8>(entropy_bits.substr(i * 8, 8)).to_ulong());
        }

        const auto hash = crypto_hash_t::sha256(entropy);

        const auto calculated_checksum_bits = std::bitset<8>(hash[0]).to_string().substr(0, checksum_bits.size());

        if (calculated_checksum_bits != checksum_bits)
        {
            throw std::runtime_error("Mnemonic checksum validation failed");
        }

        if (entropy.size() != 32)
        {
            entropy.resize(32);
        }

        return entropy;
    }

    std::vector<std::string> encode(const std::vector<unsigned char> &input, const Language::Language &language)
    {
        const auto selected_word_list = Language::select_word_list(language);

        if (input.size() != 32 && input.size() != 16)
        {
            throw std::invalid_argument("Input size must be 32-bytes");
        }

        const auto hash = crypto_hash_t::sha256(input);

        auto data_with_checksum = input;

        if (input.size() == 32)
        {
            data_with_checksum.push_back(hash[0]);
        }

        std::string binary_string;

        for (const uint8_t byte : data_with_checksum)
        {
            binary_string += std::bitset<8>(byte).to_string();
        }

        if (input.size() == 16)
        {
            binary_string += std::bitset<8>(hash[0]).to_string().substr(0, 4);
        }

        std::vector<std::string> result;

        for (size_t i = 0; i < binary_string.size(); i += 11)
        {
            std::string segment = binary_string.substr(i, 11);

            const int index = std::stoi(segment, nullptr, 2);

            result.push_back(selected_word_list[index]);
        }

        return result;
    }

    std::vector<std::string> encode(const crypto_entropy_t &wallet_seed, const Language::Language &language)
    {
        return encode(wallet_seed.serialize(), language);
    }

    std::vector<Language::Language> languages()
    {
        auto result = std::vector<Language::Language>();

        result.push_back(Language::Language::ENGLISH);

#ifndef ENGLISH_ONLY
        result.push_back(Language::Language::CHINESE_SIMPLIFIED);
        result.push_back(Language::Language::CHINESE_TRADITIONAL);
        result.push_back(Language::Language::CZECH);
        result.push_back(Language::Language::FRENCH);
        result.push_back(Language::Language::ITALIAN);
        result.push_back(Language::Language::JAPANESE);
        result.push_back(Language::Language::KOREAN);
        result.push_back(Language::Language::PORTUGUESE);
        result.push_back(Language::Language::SPANISH);
#endif

        return result;
    }

    size_t word_index(const std::string &word, const Language::Language &language)
    {
        const auto trimmed_word_list = word_list_trimmed(language);

        const auto word_list_prefix_length = Language::select_word_list_prefix(language);

        const auto trimmed_word = utf8_substr(word, word_list_prefix_length);

        auto it = std::find(trimmed_word_list.begin(), trimmed_word_list.end(), trimmed_word);

        if (it != trimmed_word_list.end())
        {
            return it - trimmed_word_list.begin();
        }
        else
        {
            return -1;
        }
    }

    std::vector<std::string> word_list(const Language::Language &language)
    {
        return Language::select_word_list(language);
    }

    std::vector<std::string> word_list_trimmed(const Language::Language &language)
    {
        // If the cache does not exist, we need to generate it
        if (cached_trimmed_words.find(language) == cached_trimmed_words.end())
        {
            const auto selected_word_list = Language::select_word_list(language);

            const auto word_list_prefix_length = Language::select_word_list_prefix(language);

            auto results = std::vector<std::string>();

            for (const auto &word : selected_word_list)
            {
                results.push_back(utf8_substr(word, word_list_prefix_length));
            }

            cached_trimmed_words.insert({language, results});
        }

        return cached_trimmed_words.at(language);
    }
} // namespace Crypto::Mnemonics
