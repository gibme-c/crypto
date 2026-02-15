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
//
// Inspired by the work of Sarang Noether at
// https://github.com/SarangNoether/skunkworks/tree/pybullet

/**
 * @file bulletproofs.h
 * @brief Bulletproof range proofs -- prove that committed values lie in [0, 2^N).
 *
 * Range proofs are essential for confidential transactions: Pedersen commitments hide
 * amounts, but without a range proof, someone could commit to a negative value and
 * effectively create money out of thin air. Bulletproofs provide a compact,
 * non-interactive zero-knowledge proof that each committed value is in the valid range
 * [0, 2^N) without revealing the value itself. They support aggregation -- proving
 * multiple values in a single proof with sublinear (logarithmic) size.
 */

#ifndef CRYPTO_RANGEPROOFS_BULLETPROOFS_H
#define CRYPTO_RANGEPROOFS_BULLETPROOFS_H

#include <types/crypto_bulletproof_t.h>

namespace Crypto::RangeProofs::Bulletproofs
{
    /**
     * Generates a Bulletproof range proof for one or more amounts.
     *
     * Produces both the proof and the corresponding Pedersen commitments. Each amount
     * is proven to be in [0, 2^N). Multiple amounts are aggregated into a single proof.
     *
     * @param amounts the plaintext values to create range proofs for
     * @param blinding_factors the blinding factors for each Pedersen commitment
     * @param N the bit-length of the range (values proven in [0, 2^N)), defaults to 64
     * @return a tuple of {proof, commitments} where commitments[i] commits to amounts[i]
     */
    std::tuple<crypto_bulletproof_t, std::vector<crypto_pedersen_commitment_t>> prove(
        const std::vector<uint64_t> &amounts,
        const std::vector<crypto_blinding_factor_t> &blinding_factors,
        size_t N = 64);

    /**
     * Batch-verifies multiple Bulletproof range proofs simultaneously.
     *
     * More efficient than verifying each proof individually thanks to shared
     * multi-exponentiation. Each proof is checked against its corresponding commitments.
     *
     * @param proofs the range proofs to verify
     * @param commitments the Pedersen commitments for each proof (one vector per proof)
     * @param N the bit-length of the range, defaults to 64
     * @return true if all proofs are valid, false if any proof fails
     */
    bool verify(
        const std::vector<crypto_bulletproof_t> &proofs,
        const std::vector<std::vector<crypto_pedersen_commitment_t>> &commitments,
        size_t N = 64);

    /**
     * Verifies a single Bulletproof range proof.
     *
     * Checks that the committed values in the given commitments are all in [0, 2^N).
     *
     * @param proof the range proof to verify
     * @param commitments the Pedersen commitments the proof was generated for
     * @param N the bit-length of the range, defaults to 64
     * @return true if the proof is valid, false otherwise
     */
    bool verify(
        const crypto_bulletproof_t &proof,
        const std::vector<crypto_pedersen_commitment_t> &commitments,
        size_t N = 64);
} // namespace Crypto::RangeProofs::Bulletproofs


#endif // CRYPTO_RANGEPROOFS_BULLETPROOFS_H
