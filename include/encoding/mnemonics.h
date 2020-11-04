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

#ifndef CRYPTO_MNEMONICS_H
#define CRYPTO_MNEMONICS_H

#include <encoding/languages/language.h>
#include <types/crypto_entropy_t.h>

namespace Crypto::Mnemonics
{
    /**
     * Decodes a vector of mnemonic phrase words into the seed it represents
     *
     * @param words
     * @param language
     * @return
     */
    crypto_entropy_t
        decode(const std::vector<std::string> &words, const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Decodes a vector of mnemonic phrase words into the bytes it represents
     *
     * @param words
     * @param language
     * @return
     */
    std::vector<unsigned char> decode_raw(
        const std::vector<std::string> &words,
        const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Encodes the given vector a vector of mnemonic phrase words
     *
     * @param input
     * @param language
     * @return
     */
    std::vector<std::string> encode(
        const std::vector<unsigned char> &input,
        const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Encodes the given seed into a vector of mnemonic phrase words
     *
     * @param wallet_seed
     * @param language
     * @return
     */
    std::vector<std::string>
        encode(const crypto_entropy_t &wallet_seed, const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Returns the supported languages
     *
     * @return
     */
    std::vector<Language::Language> languages();

    /**
     * Finds the index of the given word in the word list or returns -1 if not found
     *
     * @param word
     * @param language
     * @return
     */
    size_t word_index(const std::string &word, const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Returns the full word list
     *
     * @param language
     * @return
     */
    std::vector<std::string> word_list(const Language::Language &language = Language::Language::ENGLISH);

    /**
     * Returns the full word list but trimmed to the minimum number of characters per word
     *
     * @param language
     * @return
     */
    std::vector<std::string> word_list_trimmed(const Language::Language &language = Language::Language::ENGLISH);
} // namespace Crypto::Mnemonics

#endif
