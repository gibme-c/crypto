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
// fuzz_target_ringct.cpp
//
// Exercises RingCT commitment primitives:
//   - check_commitments_parity with adversarial commitment vectors
//   - generate_pedersen_commitment + balance round-trip
//   - generate_amount_mask, generate_commitment_blinding_factor
//   - generate_pseudo_commitments + parity verification
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_ringct(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. check_commitments_parity with random commitments --
    //
    // Random commitment vectors almost never balance; the verifier
    // must return false cleanly, never throw. This is the main
    // adversarial input surface.
    catch_safe(
        [&]
        {
            const size_t in_count = r.read_u8_range(0, 4);
            const size_t out_count = r.read_u8_range(0, 4);
            const uint64_t fee = r.read_u32_le();

            std::vector<pedersen_commitment_t> pseudo(in_count);
            std::vector<pedersen_commitment_t> output(out_count);
            for (auto &c : pseudo)
            {
                unsigned char buf[32];
                (void)r.read_bytes(buf, 32);
                c = point_t::reduce(buf);
            }
            for (auto &c : output)
            {
                unsigned char buf[32];
                (void)r.read_bytes(buf, 32);
                c = point_t::reduce(buf);
            }

            const bool ok = Crypto::RingCT::check_commitments_parity(pseudo, output, fee);
            (void)ok;
        });

    // -- 2. Mask / blinding factor derivation (never-throws) --
    catch_safe(
        [&]
        {
            unsigned char d_buf[32];
            (void)r.read_bytes(d_buf, 32);
            const scalar_t derivation = scalar_t::from_bytes_reduced(d_buf);

            const scalar_t mask = Crypto::RingCT::generate_amount_mask(derivation);
            const scalar_t blind = Crypto::RingCT::generate_commitment_blinding_factor(derivation);
            (void)mask;
            (void)blind;
        });

    // -- 3. Pedersen commitment + balance round-trip --
    //
    // Build matching input and output commitments that balance by
    // construction, then assert check_commitments_parity returns true.
    // Also flip a byte in the fee to verify the tamper-rejection path.
    catch_safe(
        [&]
        {
            unsigned char bf_buf[32];
            (void)r.read_bytes(bf_buf, 32);
            const blinding_factor_t bf = scalar_t::from_bytes_reduced(bf_buf);
            if (bf.empty())
            {
                return;
            }

            const uint64_t amount = r.read_u32_le();
            const uint64_t fee = r.read_u8_range(0, 100);
            if (amount < fee)
            {
                return; // must have amount >= fee for balance
            }

            const pedersen_commitment_t pseudo_c = Crypto::RingCT::generate_pedersen_commitment(bf, amount);
            // Output commitment with the same blinding factor and (amount - fee)
            // will balance because: pseudo = bf*G + amount*H;
            // output = bf*G + (amount-fee)*H; sum(output) + fee*H = sum(pseudo).
            const pedersen_commitment_t output_c = Crypto::RingCT::generate_pedersen_commitment(bf, amount - fee);

            if (!Crypto::RingCT::check_commitments_parity({pseudo_c}, {output_c}, fee))
            {
                throw std::runtime_error("RingCT check_commitments_parity rejected a constructed-to-balance pair");
            }

            // Wrong-fee rejection.
            if (fee > 0 && Crypto::RingCT::check_commitments_parity({pseudo_c}, {output_c}, fee - 1))
            {
                throw std::runtime_error("RingCT check_commitments_parity accepted a wrong-fee verification");
            }
        });
}
