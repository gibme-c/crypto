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
 * @file entropy_t.h
 * @brief BIP-39 entropy representation with mnemonic word encoding and decoding.
 *
 * This file defines the entropy type that sits at the root of hierarchical deterministic (HD) key
 * derivation. Entropy is 128 or 256 bits of randomness that can be encoded as a human-readable
 * sequence of mnemonic words (per BIP-39) for safe backup and recovery. The derivation chain is:
 *
 *   entropy -> mnemonic words -> seed (via PBKDF2) -> HD keys
 *
 * Mnemonic encoding supports multiple languages and includes a checksum to catch transcription errors.
 */

#ifndef ENTROPY_T_H
#define ENTROPY_T_H

#include <mnemonics/languages/language.h>
#include <types/point_t.h>

/**
 * @brief BIP-39 entropy -- the root randomness from which mnemonic words and HD keys are derived.
 *
 * Represents 128 or 256 bits of cryptographic randomness. You can generate fresh entropy, or
 * recover it from a mnemonic word sequence. The typical workflow is: generate entropy, back it up
 * as mnemonic words, then derive a seed and HD keys from it whenever you need them.
 *
 * An optional creation timestamp can be embedded in the entropy for bookkeeping purposes.
 */
struct entropy_t final : SerializablePod<32>
{
  public:
    entropy_t() = default;

    entropy_t(std::initializer_list<unsigned char> input);

    explicit entropy_t(const std::vector<unsigned char> &input);

    explicit entropy_t(const std::string &s);

    JSON_STRING_CONSTRUCTOR(entropy_t, fromJSON)

    /**
     * Generates new random entropy suitable for HD key derivation.
     *
     * You can optionally mix in additional entropy bytes (e.g., from a hardware RNG or user
     * input) for extra paranoia. If @p encode_timestamp is true, a creation timestamp is
     * embedded in the unused portion of the entropy buffer.
     *
     * @param bits the entropy strength -- 128 (12 mnemonic words) or 256 (24 words)
     * @param entropy optional additional entropy bytes to mix in
     * @param encode_timestamp if true, store a creation timestamp inside the entropy
     * @return freshly generated entropy
     */
    static entropy_t
        random(size_t bits = 256, const std::vector<unsigned char> &entropy = {}, bool encode_timestamp = true);

    /**
     * Recovers entropy from a vector of BIP-39 mnemonic words.
     *
     * This reverses the mnemonic encoding, validating the embedded checksum to catch typos
     * or word substitutions. Throws on invalid words or checksum mismatch.
     *
     * @param words the mnemonic words (12 for 128-bit, 24 for 256-bit entropy)
     * @param language the word list language to decode against (defaults to English)
     * @return the recovered entropy
     */
    static entropy_t recover(
        const std::vector<std::string> &words,
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH);

    /**
     * Recovers entropy from a space-separated mnemonic phrase string.
     *
     * Convenience overload that splits the phrase into words, then delegates to the
     * vector-based recover() method.
     *
     * @param phrase the space-separated mnemonic phrase
     * @param language the word list language to decode against (defaults to English)
     * @return the recovered entropy
     */
    static entropy_t recover(
        const std::string &phrase,
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH);

    /**
     * Returns the creation timestamp embedded in the entropy, if one was encoded.
     *
     * @return the Unix timestamp (seconds since epoch) when this entropy was generated
     */
    [[nodiscard]] uint64_t timestamp() const;

    /**
     * Serializes the entropy to a JSON writer as a hex string.
     *
     * @param writer the JSON writer to output to
     */
    JSON_TO_FUNC(toJSON) override;

    /**
     * Converts the entropy to a space-separated BIP-39 mnemonic phrase.
     *
     * This is the human-friendly representation you would write down on paper or store
     * in a secure backup. The number of words depends on the entropy size (12 or 24).
     *
     * @param language the word list language to encode with (defaults to English)
     * @return a space-separated string of mnemonic words
     */
    [[nodiscard]] std::string to_mnemonic_phrase(
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH) const;

    /**
     * Converts the entropy to a vector of individual BIP-39 mnemonic words.
     *
     * Same as to_mnemonic_phrase() but returns the words as separate strings,
     * which is handy if you need to display or process them individually.
     *
     * @param language the word list language to encode with (defaults to English)
     * @return a vector of mnemonic words (12 or 24 depending on entropy size)
     */
    [[nodiscard]] std::vector<std::string> to_mnemonic_words(
        const Crypto::Mnemonics::Language::Language &language = Crypto::Mnemonics::Language::Language::ENGLISH) const;

    /**
     * Returns the entropy as a hex-encoded string.
     * @return hex string representation of the raw entropy bytes
     */
    [[nodiscard]] std::string to_string() const override;

    /**
     * @brief Returns true if this entropy holds 128 bits of randomness.
     *
     * entropy_t is a fixed 32-byte POD. By library convention, 128-bit entropy is stored in
     * the lower 16 bytes with the upper 16 bytes zeroed (see random(128) in entropy_t.cpp).
     * This accessor is the SINGLE canonical place that distinguishes 128-bit from 256-bit
     * entropy; any code that needs to know the length (mnemonic encoding, SLIP-39 split,
     * seed derivation, etc.) MUST route through here rather than re-implementing the
     * zero-upper-half check inline.
     *
     * Callers constructing an entropy_t from externally sourced 32-byte material
     * whose upper half is zero by chance or by construction -- but whose full 32
     * bytes are meaningful -- should not rely on this accessor for SLIP-39 inputs;
     * instead pass an explicit entropy_bits override to Shamir::split / Shamir::derive_seed.
     *
     * @return true if 128-bit (upper 16 bytes all zero), false if 256-bit
     */
    [[nodiscard]] bool is_128_bit() const;

    /**
     * @brief Returns the bit-size of this entropy under the library convention.
     *
     * Convenience wrapper over is_128_bit() that returns 128 or 256 directly. Use this
     * whenever you need the numeric length rather than a boolean test.
     *
     * @return 128 if is_128_bit() is true, 256 otherwise
     */
    [[nodiscard]] size_t bits() const;
};

#endif
