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
 * @file mnemonics.h
 * @brief BIP-39 mnemonic word encoding for human-friendly key backup and recovery.
 *
 * Converts raw entropy (or a seed) into a sequence of common words drawn from a
 * standardized word list, and converts them back. Instead of asking users to write
 * down 32 hex bytes, you give them 24 English words (or another supported language)
 * that encode the same information with a built-in checksum. Supports 10 languages.
 */

#ifndef CRYPTO_MNEMONICS_H
#define CRYPTO_MNEMONICS_H

#include <encoding/languages/language.h>
#include <optional>
#include <types/crypto_entropy_t.h>

namespace Crypto::Mnemonics
{
    /**
     * Decodes a mnemonic phrase back into the entropy it represents.
     *
     * @param words the mnemonic words (typically 12 or 24 words)
     * @param language the word list language (defaults to English)
     * @return the recovered entropy
     */
    crypto_entropy_t
        decode(const std::vector<std::string> &words, const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Decodes a mnemonic phrase into raw bytes.
     *
     * Similar to decode() but returns the raw byte vector instead of a typed entropy object.
     *
     * @param words the mnemonic words
     * @param language the word list language (defaults to English)
     * @return the decoded raw bytes
     */
    std::vector<unsigned char> decode_raw(
        const std::vector<std::string> &words,
        const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Encodes raw bytes into a mnemonic phrase.
     *
     * @param input the raw bytes to encode
     * @param language the word list language (defaults to English)
     * @return the mnemonic words
     */
    std::vector<std::string> encode(
        const std::vector<unsigned char> &input,
        const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Encodes entropy into a mnemonic phrase.
     *
     * @param wallet_seed the entropy to encode
     * @param language the word list language (defaults to English)
     * @return the mnemonic words
     */
    std::vector<std::string>
        encode(const crypto_entropy_t &wallet_seed, const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Returns the list of supported mnemonic languages.
     *
     * @return a vector of available Language enum values
     */
    std::vector<Language::Language> languages();

    /**
     * Looks up a word's index in the mnemonic word list.
     *
     * Useful for validating individual words or building custom encoding logic.
     *
     * @param word the word to search for
     * @param language the word list language (defaults to English)
     * @return the 0-based index, or std::nullopt if the word is not in the list
     */
    std::optional<size_t>
        word_index(const std::string &word, const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Returns the complete BIP-39 word list for the given language.
     *
     * @param language the word list language (defaults to English)
     * @return all 2048 words in the word list
     */
    std::vector<std::string> word_list(const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Returns the word list with each word trimmed to its minimum unique prefix.
     *
     * BIP-39 word lists are designed so that each word is uniquely identifiable by its
     * first few characters. This returns those shortened forms.
     *
     * @param language the word list language (defaults to English)
     * @return the trimmed word list
     */
    std::vector<std::string> word_list_trimmed(const Language::Language &language = Language::Language::ENGLISH);
} // namespace Crypto::Mnemonics

#endif
