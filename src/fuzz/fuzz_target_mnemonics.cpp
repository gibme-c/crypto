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

// ---------------------------------------------------------------------------
// fuzz_target_mnemonics.cpp
//
// Exercises Crypto::Mnemonics encode/decode with adversarial word lists
// and language selectors. BIP-39-style mnemonic decoding is an attacker-
// facing parser in every wallet recovery flow: arbitrary word vectors
// and arbitrary language selectors MUST reject cleanly via the SAFE
// exception set, never crash.
//
// Paths exercised:
//   1. Mnemonics::decode(random_words, each_supported_language)
//      — adversarial input path. Random short strings almost never form
//      a valid BIP-39 phrase, so the vast majority of iterations hit
//      SAFE-reject branches (unknown word, wrong length, bad checksum).
//   2. Mnemonics::decode_raw(random_words, lang) — same path, different
//      return type.
//   3. Mnemonics::encode(random_bytes, lang) round-trip
//      — encode(bytes) → decode → bytes must match.
//   4. Cross-language rejection — encode in one language, decode in a
//      different language must fail. Per BIP-39 each language's word
//      list is disjoint (with extremely rare exceptions), so a decode
//      with the wrong language should either SAFE-throw ("unknown
//      word") or produce a different entropy via hash collision (in
//      which case we don't assert inequality because collisions are
//      theoretically possible).
//
// Language selection: picks from Crypto::Mnemonics::languages() using
// a fuzzer byte. When ENGLISH_ONLY is defined, languages() returns a
// single-element vector, so the selection degenerates to English only.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

namespace
{
    Crypto::Mnemonics::Language::Language pick_language(FuzzByteReader &r)
    {
        const auto langs = Crypto::Mnemonics::languages();
        if (langs.empty())
        {
            // Should never happen — languages() always returns at least
            // English — but guard anyway.
            return Crypto::Mnemonics::Language::Language::ENGLISH;
        }
        const uint8_t idx = r.read_u8();
        return langs[idx % langs.size()];
    }

    // Build a random word vector. Each word is 3-12 lowercase letters —
    // that shape occasionally hits a real dictionary word and thus
    // produces a partial parse rather than immediate "unknown word"
    // rejection, which exercises more of the decoder's path depth.
    std::vector<std::string> random_words(FuzzByteReader &r)
    {
        const size_t count = r.read_u8_range(0, 24);
        std::vector<std::string> words;
        words.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            const size_t len = r.read_u8_range(3, 12);
            std::string w;
            w.reserve(len);
            for (size_t j = 0; j < len; ++j)
            {
                // Biased toward a-z to hit the BIP-39 alphabet.
                const uint8_t b = r.read_u8();
                w.push_back(static_cast<char>('a' + (b % 26)));
            }
            words.push_back(std::move(w));
        }
        return words;
    }
} // namespace

extern "C" void fuzz_one_mnemonics(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. Mnemonics::decode(random words, random language) --
    catch_safe(
        [&]
        {
            const auto words = random_words(r);
            const auto lang = pick_language(r);

            const entropy_t e = Crypto::Mnemonics::decode(words, lang);
            (void)e;
        });

    // -- 2. Mnemonics::decode_raw(random words, random language) --
    catch_safe(
        [&]
        {
            const auto words = random_words(r);
            const auto lang = pick_language(r);

            const std::vector<unsigned char> bytes = Crypto::Mnemonics::decode_raw(words, lang);
            (void)bytes;
        });

    // -- 3. Encode/decode round-trip (128-bit path) --
    //
    // NOTE: Crypto::Mnemonics::decode_raw always returns a 32-byte
    // vector regardless of whether the input was 12 or 24 words. For a
    // 12-word (128-bit) mnemonic the first 16 bytes are the recovered
    // entropy and the last 16 are zero-padded. See
    // src/mnemonics/mnemonics.cpp:167-170. The round-trip invariant is
    // therefore "the first input.size() bytes of recovered match
    // input", not "sizes are equal". The trailing 16 bytes of the
    // 128-bit case MUST be zero.
    catch_safe(
        [&]
        {
            unsigned char ent16[16];
            (void)r.read_bytes(ent16, 16);
            const std::vector<unsigned char> input(ent16, ent16 + 16);
            const auto lang = pick_language(r);

            const auto words = Crypto::Mnemonics::encode(input, lang);
            const auto recovered = Crypto::Mnemonics::decode_raw(words, lang);

            if (recovered.size() != 32)
            {
                throw std::runtime_error("Mnemonics decode_raw did not return 32 bytes for a 12-word mnemonic");
            }
            if (std::memcmp(recovered.data(), input.data(), input.size()) != 0)
            {
                throw std::runtime_error(
                    "Mnemonics encode/decode round-trip (128-bit): first 16 bytes do not match input");
            }
            for (size_t i = input.size(); i < recovered.size(); ++i)
            {
                if (recovered[i] != 0)
                {
                    throw std::runtime_error(
                        "Mnemonics decode_raw: trailing padding is not zero for a 12-word mnemonic");
                }
            }
        });

    // -- 4. Encode/decode round-trip (256-bit path) --
    catch_safe(
        [&]
        {
            unsigned char ent32[32];
            (void)r.read_bytes(ent32, 32);
            const std::vector<unsigned char> input(ent32, ent32 + 32);
            const auto lang = pick_language(r);

            const auto words = Crypto::Mnemonics::encode(input, lang);
            const auto recovered = Crypto::Mnemonics::decode_raw(words, lang);

            if (recovered.size() != input.size() || std::memcmp(recovered.data(), input.data(), input.size()) != 0)
            {
                throw std::runtime_error(
                    "Mnemonics encode/decode round-trip (256-bit): recovered bytes do not match input");
            }
        });

    // -- 5. Cross-language rejection --
    // Encode in one language, then decode in a DIFFERENT language. The
    // dictionaries are nearly disjoint so this should SAFE-throw
    // "unknown word" with very high probability. We don't assert the
    // throw itself — we only assert that on the rare case where it DOES
    // decode successfully, the resulting entropy differs from the
    // original (hash collision would be a finding; equality would mean
    // the language selector isn't actually binding into the derivation,
    // which is a bug).
    catch_safe(
        [&]
        {
            const auto langs = Crypto::Mnemonics::languages();
            if (langs.size() < 2)
            {
                // ENGLISH_ONLY build — nothing to do.
                return;
            }

            unsigned char ent16[16];
            (void)r.read_bytes(ent16, 16);
            const std::vector<unsigned char> input(ent16, ent16 + 16);

            const auto lang_a = langs[r.read_u8() % langs.size()];
            auto lang_b = langs[r.read_u8() % langs.size()];
            if (lang_b == lang_a)
            {
                lang_b = langs[(static_cast<size_t>(lang_a) + 1) % langs.size()];
            }

            const auto words = Crypto::Mnemonics::encode(input, lang_a);

            // decode with lang_b may SAFE-throw (expected). We catch it
            // here so the "if it succeeds" branch below can run.
            std::vector<unsigned char> recovered;
            bool decoded_ok = false;
            try
            {
                recovered = Crypto::Mnemonics::decode_raw(words, lang_b);
                decoded_ok = true;
            }
            catch (const std::invalid_argument &)
            {
                // expected dominant path
            }
            catch (const std::out_of_range &)
            {
                // also acceptable
            }
            catch (const std::length_error &)
            {
                // also acceptable
            }

            if (decoded_ok && recovered == input)
            {
                // Hash collision is cryptographically negligible. If this
                // fires, the language selector isn't binding into the
                // derivation — real bug.
                throw std::runtime_error("Mnemonics cross-language decode produced the original input — "
                                         "language selector is not binding");
            }
        });
}
