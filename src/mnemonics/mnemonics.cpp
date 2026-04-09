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
 * @file mnemonics.cpp
 * @brief BIP-39 mnemonic encoding/decoding: entropy to 12/24 word phrases with SHA-256 checksum.
 */

#include <bitset>
#include <cstring>
#include <map>
#include <mnemonics/mnemonics.h>
#include <mutex>
#include <serialization.h>
#include <types/hash_t.h>
#include <unordered_map>

static std::map<Crypto::Mnemonics::Language::Language, std::vector<std::string>> cached_trimmed_words =
    std::map<Crypto::Mnemonics::Language::Language, std::vector<std::string>>();

static std::map<Crypto::Mnemonics::Language::Language, std::unordered_map<std::string, size_t>> cached_word_index_maps =
    std::map<Crypto::Mnemonics::Language::Language, std::unordered_map<std::string, size_t>>();

static std::mutex cache_lock;

// ---------------------------------------------------------------------------
// Unicode NFC normalization for BIP-39 word-list handling.
//
// PROBLEM this solves:
//
//   BIP-39 word lists for several languages (French, Spanish) contain
//   accented characters. These can be represented in two Unicode
//   normalization forms:
//
//     NFC (precomposed):  é = U+00E9        = 0xC3 0xA9        (2 bytes)
//     NFD (decomposed):   é = U+0065+U+0301 = 0x65 0xCC 0x81   (3 bytes)
//
//   A user who types or pastes a mnemonic on an OS/input method that
//   delivers NFD will fail lookup against a library word list stored
//   in NFC, because the hash map keys compare byte-for-byte. Same
//   visual text, different bytes, no match.
//
//   Separately, if the stored word list itself accidentally ends up in
//   NFD (e.g. a future edit pastes through an editor that normalizes on
//   paste), the 4-codepoint prefix-trimming that word_list_trimmed()
//   applies can collapse distinct words to the same prefix, producing
//   silent data corruption on mnemonic round-trip. The French and
//   Spanish word lists are stored in NFC form and carry warning comments
//   against NFD, but comments are not a structural guarantee.
//
// FIX — two-part, working together:
//
//   1. `normalize_nfc(s)` walks the input string and replaces every
//      known BIP-39 NFD combining-mark sequence with its precomposed
//      NFC byte sequence. The table below covers every accented
//      character that appears in any BIP-39 word list (French and
//      Spanish are the only languages with non-ASCII letters at
//      non-CJK prefix length). The function is applied at TWO sites:
//
//        a) word_list_trimmed() — on every word loaded from the
//           stored list BEFORE it is inserted into the index map.
//           If a word list file is ever accidentally committed in
//           NFD, this converts on load so the cached map stays NFC.
//
//        b) word_index() — on user-supplied input BEFORE lookup.
//           If a user supplies an NFD mnemonic, it is silently
//           normalized to NFC before hashing against the map.
//
//      The net effect: both sides of the lookup are always in NFC,
//      regardless of what form the stored file or user input is in.
//
//   2. `utf8_substr` is rewritten to count GRAPHEME CLUSTERS rather
//      than codepoints. A grapheme cluster is a base letter plus any
//      subsequent combining marks that attach to it. Under the old
//      codepoint-counting behavior, NFD `é` (base+combining) counted
//      as two characters, so a 4-character prefix truncated "aérer"
//      and "aéronef" to the same 5-byte prefix `a,e,combining,r`.
//      The new grapheme-counting behavior counts `é` (any form) as
//      one grapheme, so the prefixes become "aére" (4 graphemes) and
//      "aéro" (4 graphemes) — distinct. This is defense-in-depth on
//      top of normalize_nfc: even if a stored word list somehow
//      escaped normalization, the prefix trimming would still not
//      collide.
//
// NON-GOAL: this module does NOT attempt to handle Hangul syllable
// composition (Korean) or Katakana dakuten composition (Japanese).
// Those languages use WORD_MAX_LENGTH prefix in the BIP-39 word list
// (full-word matching, not prefix matching), so utf8_substr's
// grapheme counting is moot. For user-input normalization, BIP-39
// CJK input is typed via IMEs that deliver precomposed forms in
// practice. A full Unicode NFC normalizer would cover those cases
// correctly, but that requires the Unicode canonical composition
// table (~1500 entries) and a compile-time dependency this library
// deliberately avoids. If Korean/Japanese user reports surface the
// lookup-mismatch issue, the cleanest follow-up is to extend this
// table with the specific precomposable sequences that appear in
// the BIP-39 Korean/Japanese word lists, not to pull in full Unicode.
// ---------------------------------------------------------------------------

namespace
{
    struct nfc_pair_t
    {
        const char *nfd; // NFD byte sequence (base letter + combining mark)
        size_t nfd_len;
        const char *nfc; // NFC byte sequence (precomposed codepoint)
        size_t nfc_len;
    };

    // Every accented character that appears in any BIP-39 word list.
    // Enumeration methodology: scan src/mnemonics/languages/*.cpp for
    // non-ASCII bytes, which surfaces only French and Spanish as the
    // affected languages. French uses {é, è}; Spanish uses {á, é, í,
    // ñ, ó, ú}; union = 7 unique characters.
    //
    // Italian, Portuguese, and Czech BIP-39 word lists are fully ASCII
    // and need no entries here.
    //
    // Chinese (Simplified/Traditional), Japanese, and Korean BIP-39
    // word lists contain no combining marks — see the NON-GOAL note
    // above for why those languages are intentionally out of scope.
    constexpr nfc_pair_t k_nfc_table[] = {
        // NFD (base+combining) -------------> NFC (precomposed)
        {"\x61\xCC\x80", 3, "\xC3\xA0", 2}, // à  U+0300 → U+00E0 (a grave)
        {"\x61\xCC\x81", 3, "\xC3\xA1", 2}, // á  U+0301 → U+00E1 (a acute)
        {"\x65\xCC\x80", 3, "\xC3\xA8", 2}, // è  U+0300 → U+00E8 (e grave)
        {"\x65\xCC\x81", 3, "\xC3\xA9", 2}, // é  U+0301 → U+00E9 (e acute)
        {"\x69\xCC\x81", 3, "\xC3\xAD", 2}, // í  U+0301 → U+00ED (i acute)
        {"\x6E\xCC\x83", 3, "\xC3\xB1", 2}, // ñ  U+0303 → U+00F1 (n tilde)
        {"\x6F\xCC\x81", 3, "\xC3\xB3", 2}, // ó  U+0301 → U+00F3 (o acute)
        {"\x75\xCC\x81", 3, "\xC3\xBA", 2}, // ú  U+0301 → U+00FA (u acute)
    };

    // Returns true iff a UTF-8 leader byte + optional follow byte
    // represents a codepoint in the Combining Diacritical Marks block
    // (U+0300 through U+036F). This block covers the overwhelming
    // majority of combining marks used by Latin-script languages,
    // including every combining mark needed for NFD of the BIP-39
    // French and Spanish word lists. Other combining-mark blocks
    // (U+1AB0-U+1AFF, U+1DC0-U+1DFF, U+20D0-U+20FF, U+FE20-U+FE2F) are
    // intentionally NOT recognized — they never appear in BIP-39 word
    // lists and adding them here would be dead code.
    //
    // In UTF-8:
    //   U+0300-U+033F encodes as 0xCC 0x80-0xBF (2 bytes)
    //   U+0340-U+036F encodes as 0xCD 0x80-0xAF (2 bytes)
    inline bool is_combining_mark_start(unsigned char b0, unsigned char b1) noexcept
    {
        if (b0 == 0xCC)
        {
            return true;
        }
        if (b0 == 0xCD && b1 <= 0xAF)
        {
            return true;
        }
        return false;
    }

    // Convert any NFD sequences in `input` that match a k_nfc_table
    // entry into their NFC precomposed forms. Bytes that don't match
    // any table entry are passed through unchanged, so this function
    // is idempotent on fully-NFC input: normalize_nfc(NFC) == NFC.
    std::string normalize_nfc(const std::string &input)
    {
        std::string out;
        out.reserve(input.size());
        size_t i = 0;
        while (i < input.size())
        {
            bool replaced = false;
            for (const auto &pair : k_nfc_table)
            {
                if (i + pair.nfd_len <= input.size() && std::memcmp(input.data() + i, pair.nfd, pair.nfd_len) == 0)
                {
                    out.append(pair.nfc, pair.nfc_len);
                    i += pair.nfd_len;
                    replaced = true;
                    break;
                }
            }
            if (replaced)
            {
                continue;
            }

            // No NFD match — copy one UTF-8 codepoint as-is. Walk one
            // codepoint forward based on the leader byte.
            const unsigned char c = static_cast<unsigned char>(input[i]);
            size_t char_len = 1;
            if ((c & 0x80) == 0x00)
            {
                char_len = 1;
            }
            else if ((c & 0xE0) == 0xC0)
            {
                char_len = 2;
            }
            else if ((c & 0xF0) == 0xE0)
            {
                char_len = 3;
            }
            else if ((c & 0xF8) == 0xF0)
            {
                char_len = 4;
            }
            // Bounds-clamp: if the declared codepoint runs past the
            // end of the input, copy what remains and stop. This is
            // defensive against truncated/malformed UTF-8.
            if (i + char_len > input.size())
            {
                char_len = input.size() - i;
            }
            out.append(input, i, char_len);
            i += char_len;
        }
        return out;
    }
} // namespace

// Substring by UTF-8 GRAPHEME CLUSTER count (not byte count, not
// codepoint count). A grapheme cluster is one base letter plus any
// subsequent combining marks in the U+0300-U+036F range that attach
// to it. The old implementation counted codepoints, which produced
// prefix collisions for NFD-encoded accented words (see the full
// rationale in the block comment above normalize_nfc).
static inline std::string utf8_substr(const std::string &str, size_t length)
{
    if (length == 0 || str.empty())
    {
        return "";
    }

    size_t byte_pos = 0;
    size_t grapheme_count = 0;

    while (byte_pos < str.size() && grapheme_count < length)
    {
        // Decode one UTF-8 codepoint at byte_pos. This becomes the
        // grapheme cluster's base.
        const unsigned char c = static_cast<unsigned char>(str[byte_pos]);
        size_t char_len;
        if ((c & 0x80) == 0x00)
        {
            char_len = 1;
        }
        else if ((c & 0xE0) == 0xC0)
        {
            char_len = 2;
        }
        else if ((c & 0xF0) == 0xE0)
        {
            char_len = 3;
        }
        else if ((c & 0xF8) == 0xF0)
        {
            char_len = 4;
        }
        else
        {
            return ""; // invalid utf8 leader byte
        }

        if (byte_pos + char_len > str.size())
        {
            return ""; // truncated
        }

        // Advance past the base codepoint.
        byte_pos += char_len;
        grapheme_count++;

        // Absorb any trailing combining marks into the current grapheme
        // cluster. They attach to the preceding base and do NOT count
        // as separate graphemes, so we advance byte_pos but not
        // grapheme_count.
        while (byte_pos + 1 < str.size())
        {
            const unsigned char b0 = static_cast<unsigned char>(str[byte_pos]);
            const unsigned char b1 = static_cast<unsigned char>(str[byte_pos + 1]);
            if (!is_combining_mark_start(b0, b1))
            {
                break;
            }
            byte_pos += 2;
        }
    }

    return str.substr(0, byte_pos);
}

namespace Crypto::Mnemonics
{
    entropy_t decode(const std::vector<std::string> &words, const Language::Language &language)
    {
        const auto result = decode_raw(words, language);

        Serialization::deserializer_t reader(result);

        return reader.pod<entropy_t>();
    }

    std::vector<unsigned char> decode_raw(const std::vector<std::string> &words, const Language::Language &language)
    {
        if (words.size() != 24 && words.size() != 12)
        {
            throw std::invalid_argument("Mnemonic must contain exactly 12 or 24 words");
        }

        std::string binary_string;

        for (const std::string &word : words)
        {
            const auto index = word_index(word, language);

            if (!index.has_value())
            {
                throw std::invalid_argument("Invalid word in mnemonic");
            }

            binary_string += std::bitset<11>(*index).to_string();
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

        const auto hash = hash_t::sha256(entropy);

        const auto calculated_checksum_bits = std::bitset<8>(hash[0]).to_string().substr(0, checksum_bits.size());

        if (calculated_checksum_bits != checksum_bits)
        {
            // Malformed-input contract.
            throw std::invalid_argument("Mnemonic checksum validation failed");
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

        const auto hash = hash_t::sha256(input);

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

    std::vector<std::string> encode(const entropy_t &wallet_seed, const Language::Language &language)
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

    std::optional<size_t> word_index(const std::string &word, const Language::Language &language)
    {
        const auto word_list_prefix_length = Language::select_word_list_prefix(language);

        // Normalize the caller-supplied word to NFC before prefix
        // trimming and lookup. The cached index map is populated from
        // NFC-normalized words (see word_list_trimmed below), so this
        // step makes the user's input match the stored form even when
        // the user's OS/input method delivers NFD. See the normalize_nfc
        // block comment at the top of this file for the full rationale.
        const auto normalized_word = normalize_nfc(word);

        const auto trimmed_word = utf8_substr(normalized_word, word_list_prefix_length);

        // Ensure the word index map is built (calls word_list_trimmed which populates the cache)
        word_list_trimmed(language);

        {
            std::lock_guard<std::mutex> lock(cache_lock);

            const auto &index_map = cached_word_index_maps.at(language);
            auto it = index_map.find(trimmed_word);
            return (it != index_map.end()) ? std::optional<size_t>(it->second) : std::nullopt;
        }
    }

    std::vector<std::string> word_list(const Language::Language &language)
    {
        return Language::select_word_list(language);
    }

    std::vector<std::string> word_list_trimmed(const Language::Language &language)
    {
        std::lock_guard<std::mutex> lock(cache_lock);

        // If the cache does not exist, we need to generate it
        if (cached_trimmed_words.find(language) == cached_trimmed_words.end())
        {
            const auto selected_word_list = Language::select_word_list(language);

            const auto word_list_prefix_length = Language::select_word_list_prefix(language);

            auto results = std::vector<std::string>();
            results.reserve(selected_word_list.size());

            // Normalize each stored word to NFC before trimming. This is
            // defense-in-depth against a future edit that accidentally
            // commits a word-list file in NFD form. With this step in
            // place, even if someone re-introduces NFD to a word-list
            // file, the cached map stays in NFC and the encode/decode
            // round-trip remains correct. See the normalize_nfc block
            // comment at the top of this file for the full rationale.
            for (const auto &word : selected_word_list)
            {
                results.push_back(utf8_substr(normalize_nfc(word), word_list_prefix_length));
            }

            cached_trimmed_words.insert({language, results});

            // Build O(1) lookup map for word_index
            std::unordered_map<std::string, size_t> index_map;
            index_map.reserve(results.size());

            for (size_t i = 0; i < results.size(); ++i)
            {
                index_map[results[i]] = i;
            }

            cached_word_index_maps.insert({language, std::move(index_map)});
        }

        return cached_trimmed_words.at(language);
    }
} // namespace Crypto::Mnemonics
