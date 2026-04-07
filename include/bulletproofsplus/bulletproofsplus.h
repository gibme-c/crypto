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
//
// Inspired by the work of Sarang Noether at
// https://github.com/SarangNoether/skunkworks/tree/pybullet-plus

/**
 * @file bulletproofsplus.h
 * @brief Bulletproofs+ range proofs -- a more efficient successor to Bulletproofs.
 *
 * Bulletproofs+ use a weighted inner product argument to achieve smaller proof sizes
 * and faster verification compared to the original Bulletproofs, while providing
 * the same guarantee: each committed value lies in [0, 2^N). The API mirrors the
 * original Bulletproofs interface (prove/verify/batch-verify).
 */

#ifndef CRYPTO_RANGEPROOFS_BULLETPROOFS_PLUS_H
#define CRYPTO_RANGEPROOFS_BULLETPROOFS_PLUS_H

#include <bulletproofsplus/bulletproof_plus_t.h>

namespace Crypto::RangeProofs::BulletproofsPlus
{
    /**
     * Generates a Bulletproofs+ range proof for one or more amounts.
     *
     * Produces both the proof and the corresponding Pedersen commitments. Each amount
     * is proven to be in [0, 2^N). Multiple amounts are aggregated into a single proof.
     *
     * @param amounts the plaintext values to create range proofs for
     * @param blinding_factors the blinding factors for each Pedersen commitment
     * @param N the bit-length of the range (values proven in [0, 2^N)), defaults to 64
     * @return a tuple of {proof, commitments} where commitments[i] commits to amounts[i]
     */
    std::tuple<bulletproof_plus_t, std::vector<pedersen_commitment_t>> prove(
        const std::vector<uint64_t> &amounts,
        const std::vector<blinding_factor_t> &blinding_factors,
        size_t N = 64);

    /**
     * Batch-verifies multiple Bulletproofs+ range proofs simultaneously.
     *
     * More efficient than individual verification thanks to shared multi-exponentiation.
     *
     * @param proofs the range proofs to verify
     * @param commitments the Pedersen commitments for each proof (one vector per proof)
     * @param N the bit-length of the range, defaults to 64
     * @return true if all proofs are valid, false if any proof fails
     */
    bool verify(
        const std::vector<bulletproof_plus_t> &proofs,
        const std::vector<std::vector<pedersen_commitment_t>> &commitments,
        size_t N = 64);

    /**
     * Verifies a single Bulletproofs+ range proof.
     *
     * @param proof the range proof to verify
     * @param commitments the Pedersen commitments the proof was generated for
     * @param N the bit-length of the range, defaults to 64
     * @return true if the proof is valid, false otherwise
     */
    bool verify(const bulletproof_plus_t &proof, const std::vector<pedersen_commitment_t> &commitments, size_t N = 64);
} // namespace Crypto::RangeProofs::BulletproofsPlus


#endif // CRYPTO_RANGEPROOFS_BULLETPROOFS_PLUS_H
