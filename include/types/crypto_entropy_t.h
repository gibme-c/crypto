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

#ifndef CRYPTO_ENTROPY_T
#define CRYPTO_ENTROPY_T

#include <encoding/languages/language.h>
#include <types/crypto_point_t.h>

struct crypto_entropy_t final : SerializablePod<32>
{
  public:
    crypto_entropy_t() = default;

    crypto_entropy_t(std::initializer_list<unsigned char> input);

    explicit crypto_entropy_t(const std::vector<unsigned char> &input);

    explicit crypto_entropy_t(const std::string &s);

    JSON_STRING_CONSTRUCTOR(crypto_entropy_t, fromJSON)

    /**
     * Generates a random entropy with entropy
     *
     * @param entropy
     * @param bits
     * @param encode_timestamp
     * @return
     */
    static crypto_entropy_t
        random(size_t bits = 256, const std::vector<unsigned char> &entropy = {}, bool encode_timestamp = true);

    /**
     * Recovers a entropy from a vector of words
     *
     * @param words
     * @param language
     * @return
     */
    static crypto_entropy_t recover(
        const std::vector<std::string> &words,
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH);

    /**
     * Recovers a entropy from a string of words
     *
     * @param phrase
     * @param language
     * @return
     */
    static crypto_entropy_t recover(
        const std::string &phrase,
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH);

    /**
     * Returns the timestamp the entropy was created
     *
     * @return
     */
    [[nodiscard]] uint64_t timestamp() const;

    /**
     * Writes the pod to the supplied json writer as a string
     *
     * @param writer
     */
    JSON_TO_FUNC(toJSON) override;

    /**
     * Converts the entropy to mnemonic phrase of words
     *
     * @param language
     * @return
     */
    [[nodiscard]] std::string to_mnemonic_phrase(
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH) const;

    /**
     * Converts the entropy to a vector of mnemonic words
     *
     * @param language
     * @return
     */
    [[nodiscard]] std::vector<std::string> to_mnemonic_words(
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH) const;

    /**
     * Returns the entropy as a hex encoded string
     * @return
     */
    [[nodiscard]] std::string to_string() const override;

  private:
    [[nodiscard]] bool is_128_bit() const;
};

#endif
