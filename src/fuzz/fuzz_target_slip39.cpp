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
// fuzz_target_slip39.cpp
//
// Exercises Crypto::Mnemonics::Shamir (SLIP-39) split/combine with
// adversarial share word lists and passphrases. SLIP-39 decoding is the
// "restore wallet" parser — adversarial input must reject cleanly,
// never crash.
//
// Paths exercised:
//   1. Shamir::validate_share(random words)     — returns bool; MUST
//      NOT throw for any input per docstring.
//   2. Shamir::combine(random share vector, random passphrase)
//      — should SAFE-throw on malformed / insufficient / mismatched
//      shares.
//   3. Shamir::split then Shamir::combine round-trip — recovers the
//      original entropy exactly.
//   4. Split then combine with wrong passphrase — must SAFE-throw
//      "share digest verification failed".
//   5. Below-threshold combine — must SAFE-throw (too few shares).
//
// Iteration cost: Shamir::split invokes PBKDF2 with configurable
// iterations. We pick iteration_exponent=0 (PBKDF2 count = 2500) which
// is the minimum; even at that level, split() on a single iteration
// takes milliseconds. To keep the fuzz target fast we only exercise
// split() in a small fraction of iterations (the fuzzer byte chooses).
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
    std::vector<std::string> random_slip39_words(FuzzByteReader &r, size_t min_count, size_t max_count)
    {
        const size_t count = r.read_u8_range(static_cast<uint8_t>(min_count), static_cast<uint8_t>(max_count));
        std::vector<std::string> words;
        words.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            const size_t len = r.read_u8_range(3, 8);
            std::string w;
            w.reserve(len);
            for (size_t j = 0; j < len; ++j)
            {
                const uint8_t b = r.read_u8();
                w.push_back(static_cast<char>('a' + (b % 26)));
            }
            words.push_back(std::move(w));
        }
        return words;
    }

    std::string random_passphrase(FuzzByteReader &r, size_t max_len)
    {
        const size_t n = r.read_u8_range(0, static_cast<uint8_t>(max_len));
        const auto buf = r.read_vector(n);
        return std::string(reinterpret_cast<const char *>(buf.data()), buf.size());
    }
} // namespace

extern "C" void fuzz_one_slip39(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. validate_share(random words) must never throw --
    catch_safe(
        [&]
        {
            const auto words = random_slip39_words(r, 0, 40);
            const bool ok = Crypto::Mnemonics::Shamir::validate_share(words);
            (void)ok;
        });

    // -- 2. combine(random share vector, random passphrase) — should
    // SAFE-throw on the overwhelming majority of inputs. --
    catch_safe(
        [&]
        {
            const size_t share_count = r.read_u8_range(0, 8);
            std::vector<std::vector<std::string>> shares;
            shares.reserve(share_count);
            for (size_t i = 0; i < share_count; ++i)
            {
                shares.push_back(random_slip39_words(r, 20, 33));
            }
            const std::string passphrase = random_passphrase(r, 16);

            const entropy_t e = Crypto::Mnemonics::Shamir::combine(shares, passphrase);
            (void)e;
        });

    // -- 3. Split + combine round-trip --
    //
    // Only runs when a fuzzer byte opts in, because split() runs PBKDF2
    // which dominates iteration cost. The opt-in bit gives us periodic
    // round-trip coverage without burning wall-clock on every iteration.
    const bool run_roundtrip = (r.read_u8() & 0x3F) == 0; // ~1.5% of iters
    if (run_roundtrip)
    {
        catch_safe(
            [&]
            {
                unsigned char ent_buf[16];
                (void)r.read_bytes(ent_buf, 16);
                const entropy_t original(std::vector<unsigned char>(ent_buf, ent_buf + 16));

                const std::string passphrase = random_passphrase(r, 8);
                // Threshold 2 of 3 — the smallest non-trivial config.
                const auto shares = Crypto::Mnemonics::Shamir::split(original, 2, 3, passphrase, 0, true, 0);

                if (shares.size() != 3)
                {
                    throw std::runtime_error("SLIP-39 split did not produce 3 shares");
                }

                // Take shares 0 and 2 (skip 1) — the order must not matter.
                const std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
                const entropy_t recovered = Crypto::Mnemonics::Shamir::combine(subset, passphrase);

                if (recovered.serialize() != original.serialize())
                {
                    throw std::runtime_error("SLIP-39 split/combine round-trip did not recover entropy");
                }
            });

        // -- 4. Wrong-passphrase rejection --
        catch_safe(
            [&]
            {
                unsigned char ent_buf[16];
                (void)r.read_bytes(ent_buf, 16);
                const entropy_t original(std::vector<unsigned char>(ent_buf, ent_buf + 16));

                const std::string pw_correct = "correct horse";
                const std::string pw_wrong = "battery staple";

                const auto shares = Crypto::Mnemonics::Shamir::split(original, 2, 2, pw_correct, 0, true, 0);
                if (shares.size() != 2)
                {
                    throw std::runtime_error("SLIP-39 split (T=2,N=2) did not produce 2 shares");
                }

                bool recovered_ok = false;
                try
                {
                    const entropy_t recovered = Crypto::Mnemonics::Shamir::combine(shares, pw_wrong);
                    // Wrong passphrase should yield a DIFFERENT entropy
                    // without throwing — SLIP-39 masks with the
                    // passphrase before Shamir, so wrong passphrase
                    // produces garbage entropy. We assert only that
                    // wrong-pw garbage != original.
                    if (recovered.serialize() == original.serialize())
                    {
                        throw std::runtime_error("SLIP-39 wrong-passphrase combine returned the original entropy "
                                                 "(passphrase is not binding)");
                    }
                    recovered_ok = true;
                }
                catch (const std::invalid_argument &)
                {
                    // acceptable — some passphrase combinations trip
                    // the share digest check
                }
                catch (const std::out_of_range &)
                {
                    // acceptable
                }
                (void)recovered_ok;
            });

        // -- 5. Below-threshold combine — must SAFE-throw --
        catch_safe(
            [&]
            {
                unsigned char ent_buf[16];
                (void)r.read_bytes(ent_buf, 16);
                const entropy_t original(std::vector<unsigned char>(ent_buf, ent_buf + 16));

                const auto shares = Crypto::Mnemonics::Shamir::split(original, 3, 5, "", 0, true, 0);
                if (shares.size() != 5)
                {
                    throw std::runtime_error("SLIP-39 split (T=3,N=5) did not produce 5 shares");
                }

                // Only 2 shares — below threshold of 3.
                const std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};

                bool recovered_ok = false;
                try
                {
                    (void)Crypto::Mnemonics::Shamir::combine(subset, "");
                    recovered_ok = true;
                }
                catch (const std::invalid_argument &)
                {
                    // expected
                }
                catch (const std::out_of_range &)
                {
                    // also acceptable
                }

                if (recovered_ok)
                {
                    throw std::runtime_error("SLIP-39 below-threshold combine succeeded — threshold is not binding");
                }
            });
    }
}
