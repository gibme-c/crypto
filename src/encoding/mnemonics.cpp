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
    size_t calculate_checksum_index(const std::vector<std::string> &words, const Language::Language &language)
    {
        const auto word_list_size = Language::select_word_list_size(language);

        const auto word_list_prefix_length = Language::select_word_list_prefix(language);

        std::string temp;

        for (const auto &word : words)
        {
            temp += utf8_substr(word, word_list_prefix_length);
        }

        const auto checksum = crypto_hash_t::sha3(temp.data(), temp.size()).to_uint256_t();

        return uint32_t(checksum % word_list_size);
    }

    crypto_seed_t decode(const std::vector<std::string> &words, const Language::Language &language)
    {
        const auto result = decode_raw(words, language);

        Serialization::deserializer_t reader(result);

        return reader.pod<crypto_seed_t>();
    }

    std::vector<unsigned char> decode_raw(const std::vector<std::string> &words, const Language::Language &language)
    {
        const auto selected_word_list = Language::select_word_list(language);

        const auto word_list_size = Language::select_word_list_size(language);

        if (words.size() < 2 || (words.size() - 1) % 3 != 0)
        {
            return {false, {}, 0};
        }

        Serialization::serializer_t result;

        try
        {
            const auto &last = words.back();

            const auto temp_words = std::vector<std::string>(words.begin(), words.end() - 1);

            const auto checksum_index = calculate_checksum_index(temp_words, language);

            if (last != selected_word_list[checksum_index])
            {
                return {false, {}, 0};
            }

            for (size_t i = 0; i < temp_words.size(); i += 3)
            {
                const auto w1 = word_index(temp_words[i], language);

                const auto w2 = word_index(temp_words[i + 1], language);

                const auto w3 = word_index(temp_words[i + 2], language);

                if (w1 == -1 || w2 == -1 || w3 == -1)
                {
                    return {false, {}, 0};
                }

                const auto &n = word_list_size;

                const auto x = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n);

                if (x % word_list_size != w1)
                {
                    return {false, {}, 0};
                }

                result.uint32(x);
            }
        }
        catch (const std::exception &e)
        {
            PRINTF(e.what())

            return {false, {}, {}};
        }

        return result.vector();
    }

    std::vector<std::string> encode(const std::vector<unsigned char> &input, const Language::Language &language)
    {
        const auto selected_word_list = Language::select_word_list(language);

        const auto word_list_size = Language::select_word_list_size(language);

        if (input.size() % 4 != 0)
        {
            throw std::invalid_argument("Input size must be a multiple of 4 bytes");
        }

        std::vector<std::string> result;

        // easy reader for plucking out uint32_t values
        Serialization::deserializer_t reader(input);

        while (reader.unread_bytes() > 0)
        {
            const auto x = reader.uint32();

            const auto w1 = (x % word_list_size);

            result.push_back(selected_word_list[w1]);

            const auto w2 = (uint32_t(x / word_list_size) + w1) % word_list_size;

            result.push_back(selected_word_list[w2]);

            const auto w3 = (uint32_t(uint32_t(x / word_list_size) / word_list_size) + w2) % word_list_size;

            result.push_back(selected_word_list[w3]);
        }

        const auto checksum_index = calculate_checksum_index(result, language);

        result.push_back(selected_word_list[checksum_index]);

        return result;
    }

    std::vector<std::string> encode(const crypto_seed_t &wallet_seed, const Language::Language &language)
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
