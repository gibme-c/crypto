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
 * @file dleq.h
 * @brief Discrete Log Equality (DLEQ) proof generation and verification (Chaum-Pedersen).
 *
 * Proves that two points A = aG and B = aH share the same discrete logarithm `a`
 * with respect to base points G and H, without revealing `a`.
 */

#ifndef CRYPTO_DLEQ_H
#define CRYPTO_DLEQ_H

#include <types/crypto_dleq_proof_t.h>
#include <types/crypto_point_t.h>

namespace Crypto::DLEQ
{
    /**
     * Generates a DLEQ proof that A = secret*G and B = secret*H share the same discrete log.
     *
     * @param secret the shared discrete logarithm scalar
     * @param G first base point
     * @param H second base point
     * @return the DLEQ proof
     */
    crypto_dleq_proof_t generate_proof(
        const crypto_scalar_t &secret,
        const crypto_point_t &G,
        const crypto_point_t &H);

    /**
     * Verifies a DLEQ proof that A and B share the same discrete log w.r.t. G and H.
     *
     * @param A first public point (should equal secret*G)
     * @param B second public point (should equal secret*H)
     * @param G first base point
     * @param H second base point
     * @param proof the DLEQ proof to verify
     * @return true if the proof is valid
     */
    bool check_proof(
        const crypto_point_t &A,
        const crypto_point_t &B,
        const crypto_point_t &G,
        const crypto_point_t &H,
        const crypto_dleq_proof_t &proof);
} // namespace Crypto::DLEQ

#endif // CRYPTO_DLEQ_H
