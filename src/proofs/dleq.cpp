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
 * @file dleq.cpp
 * @brief DLEQ proof generation and verification (Chaum-Pedersen protocol).
 */

#include <crypto_constants.h>
#include <helpers/scalar_transcript_t.h>
#include <proofs/dleq.h>

namespace Crypto::DLEQ
{
    crypto_dleq_proof_t generate_proof(const crypto_scalar_t &secret, const crypto_point_t &G, const crypto_point_t &H)
    {
        SCALAR_NZ_OR_THROW(secret);

        const auto A = secret * G;
        const auto B = secret * H;

    try_again:
        // Derive nonce k from domain, secret, and fresh entropy
        scalar_transcript_t k_transcript(DLEQ_DOMAIN_0, secret, crypto_scalar_t::random());

        auto k = k_transcript.challenge();

        if (!k.valid())
        {
            goto try_again;
        }

        // Commitments: R1 = kG, R2 = kH
        const auto R1 = k * G;
        const auto R2 = k * H;

        // Challenge: c = H(domain, G, H, A, B, R1, R2)
        scalar_transcript_t challenge_transcript(DLEQ_DOMAIN_0);
        challenge_transcript.update(G, H);
        challenge_transcript.update(A, B);
        challenge_transcript.update(R1, R2);

        const auto c = challenge_transcript.challenge();

        if (!c.valid())
        {
            goto try_again;
        }

        // Response: s = k + c * secret
        const auto s = k + (c * secret);

        return {c, s};
    }

    bool check_proof(
        const crypto_point_t &A,
        const crypto_point_t &B,
        const crypto_point_t &G,
        const crypto_point_t &H,
        const crypto_dleq_proof_t &proof)
    {
        if (!proof.c.valid() || !proof.s.valid())
        {
            return false;
        }

        if (!A.check_subgroup() || !B.check_subgroup() || !G.check_subgroup() || !H.check_subgroup())
        {
            return false;
        }

        // Reconstruct: R1' = sG - cA, R2' = sH - cB
        const auto neg_c = crypto_scalar_t() - proof.c;
        const auto R1_prime = (proof.s * G) + (neg_c * A);
        const auto R2_prime = (proof.s * H) + (neg_c * B);

        // Recompute challenge
        scalar_transcript_t challenge_transcript(DLEQ_DOMAIN_0);
        challenge_transcript.update(G, H);
        challenge_transcript.update(A, B);
        challenge_transcript.update(R1_prime, R2_prime);

        const auto c_prime = challenge_transcript.challenge();

        if (!c_prime.valid())
        {
            return false;
        }

        return !(c_prime - proof.c).is_nonzero();
    }
} // namespace Crypto::DLEQ
