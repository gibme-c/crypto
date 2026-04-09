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
// fuzz_target_bp.cpp
//
// Exercises Bulletproofs prove/verify with adversarial inputs. prove()
// is expensive (tens of milliseconds at N=8), so the round-trip is
// throttled to ~1.5% of iterations via an opt-in fuzzer bit. Every
// iteration still exercises the cheap byte-ctor adversarial path.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_bp(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. byte ctor --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 255);
            const auto buf = r.read_vector(n);
            const bulletproof_t p(buf);
            (void)p;
        });

    // -- 2. Throttled round-trip --
    const bool do_roundtrip = (r.read_u8() & 0x3F) == 0; // ~1.5%
    if (!do_roundtrip)
    {
        return;
    }

    catch_safe(
        [&]
        {
            // N=8 → amounts in [0, 256). Cheapest non-trivial BP size.
            constexpr size_t N = 8;
            constexpr size_t count = 2; // aggregated range proof over 2 commitments
            std::vector<uint64_t> amounts(count);
            std::vector<blinding_factor_t> blindings(count);
            for (size_t i = 0; i < count; ++i)
            {
                amounts[i] = r.read_u8() & 0xFF; // in [0, 256), always valid for N=8
                unsigned char bf_buf[32];
                (void)r.read_bytes(bf_buf, 32);
                blindings[i] = scalar_t::from_bytes_reduced(bf_buf);
                if (blindings[i].empty())
                {
                    return;
                }
            }

            auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove(amounts, blindings, N);

            if (!Crypto::RangeProofs::Bulletproofs::verify(proof, commitments, N))
            {
                throw std::runtime_error("Bulletproofs round-trip: verify rejected a fresh proof");
            }

            // Wrong-N rejection: verifying at a different N should fail.
            if (Crypto::RangeProofs::Bulletproofs::verify(proof, commitments, 16))
            {
                throw std::runtime_error("Bulletproofs verify accepted proof at wrong N (8 vs 16)");
            }

            // Tamper: mutate one commitment and re-verify.
            if (!commitments.empty())
            {
                auto tampered = commitments;
                tampered[0] = tampered[0] + Crypto::G;
                if (Crypto::RangeProofs::Bulletproofs::verify(proof, tampered, N))
                {
                    throw std::runtime_error("Bulletproofs verify accepted a tampered commitment vector");
                }
            }
        });
}
