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
 * @file ringct.h
 * @brief RingCT (Ring Confidential Transactions) primitives for hiding transaction amounts.
 *
 * Provides Pedersen commitments and amount masking for privacy-preserving transactions.
 * A Pedersen commitment `C = bG + vH` hides a value `v` behind a blinding factor `b`,
 * while preserving additive homomorphism -- you can verify that the sum of input
 * commitments equals the sum of output commitments without ever revealing the actual
 * values. This is the foundation that lets you prove "no money was created or destroyed"
 * without disclosing how much was transferred.
 */

#ifndef CRYPTO_RINGCT_H
#define CRYPTO_RINGCT_H

#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

namespace Crypto::RingCT
{
    /**
     * Verifies that commitments balance: sum(pseudo) == sum(output) + fee*H.
     *
     * This is the core conservation check for confidential transactions. Because
     * Pedersen commitments are additively homomorphic, you can verify that inputs
     * and outputs balance without knowing any of the hidden amounts.
     *
     * @param pseudo_commitments the input-side commitments (one per input)
     * @param output_commitments the output-side commitments (one per output)
     * @param transaction_fee the plaintext fee (committed with a zero blinding factor)
     * @return true if the commitment sums balance, false otherwise
     */
    bool check_commitments_parity(
        const std::vector<crypto_pedersen_commitment_t> &pseudo_commitments,
        const std::vector<crypto_pedersen_commitment_t> &output_commitments,
        uint64_t transaction_fee);

    /**
     * Derives a deterministic amount mask from a shared derivation scalar.
     *
     * The amount mask is XORed with the actual amount to produce a masked (encrypted)
     * amount that only the recipient (who knows the derivation scalar) can decode.
     *
     * @param derivation_scalar the shared secret scalar between sender and recipient
     * @return the amount mask scalar
     */
    crypto_scalar_t generate_amount_mask(const crypto_scalar_t &derivation_scalar);

    /**
     * Derives a deterministic blinding factor from a shared derivation scalar.
     *
     * This blinding factor is used as the `b` in a Pedersen commitment `C = bG + vH`,
     * allowing the recipient to reconstruct the commitment independently.
     *
     * @param derivation_scalar the shared secret scalar between sender and recipient
     * @return the commitment blinding factor
     */
    crypto_blinding_factor_t generate_commitment_blinding_factor(const crypto_scalar_t &derivation_scalar);

    /**
     * Generates a Pedersen commitment: `C = y*G + a*H`.
     *
     * The blinding factor `y` hides the amount `a` on the curve. Given only `C`, an
     * observer cannot recover `a` without knowing `y` (this is the discrete log problem).
     *
     * @param blinding_factor the secret blinding factor `y`
     * @param amount the plaintext amount `a` to commit to
     * @return the Pedersen commitment point `C`
     */
    crypto_pedersen_commitment_t
        generate_pedersen_commitment(const crypto_blinding_factor_t &blinding_factor, const uint64_t &amount);

    /**
     * Generates pseudo commitments for the input side of a transaction.
     *
     * Each input gets a random blinding factor except the last, which is chosen so
     * that the sum of input blinding factors equals the sum of output blinding factors.
     * This ensures the commitments balance (sum to zero) without revealing amounts.
     *
     * @param input_amounts the plaintext input amounts
     * @param output_blinding_factors the blinding factors already used for output commitments
     * @return a tuple of {pseudo blinding factors, pseudo commitments}
     */
    std::tuple<std::vector<crypto_blinding_factor_t>, std::vector<crypto_pedersen_commitment_t>>
        generate_pseudo_commitments(
            const std::vector<uint64_t> &input_amounts,
            const std::vector<crypto_blinding_factor_t> &output_blinding_factors);

    /**
     * Toggles an amount between masked and unmasked form.
     *
     * This is a symmetric XOR-like operation: applying it once masks (encrypts) the
     * amount, and applying it again with the same mask unmasks (decrypts) it.
     *
     * @param amount_mask the mask scalar (derived from a shared secret)
     * @param amount the amount to mask or unmask (as a scalar)
     * @return the toggled amount scalar
     */
    crypto_scalar_t toggle_masked_amount(const crypto_scalar_t &amount_mask, const crypto_scalar_t &amount);
} // namespace Crypto::RingCT

#endif // CRYPTO_RINGCT_H
