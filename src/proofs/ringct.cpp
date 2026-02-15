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

/**
 * @file ringct.cpp
 * @brief RingCT primitives: Pedersen commitments (C = vH + bG), amount masking, and pseudo commitment generation.
 */

#include <crypto_constants.h>
#include <helpers/scalar_transcript_t.h>
#include <proofs/ringct.h>

namespace Crypto::RingCT
{
    bool check_commitments_parity(
        const std::vector<crypto_pedersen_commitment_t> &pseudo_commitments,
        const std::vector<crypto_pedersen_commitment_t> &output_commitments,
        uint64_t transaction_fee)
    {
        // tally up the pseudo commitments
        const auto pseudo_total = crypto_point_vector_t(pseudo_commitments).sum();

        // tally up the output commitments
        const auto output_total = crypto_point_vector_t(output_commitments).sum();

        // construct the fee commitment
        const auto fee_commitment = generate_pedersen_commitment(Crypto::ZERO, transaction_fee);

        /**
         * Check if the sum of the pseudo output commitments is equal to the
         * sum of the output commitments plus the commitment to the transaction fee
         */
        return pseudo_total == output_total + fee_commitment;
    }

    crypto_scalar_t generate_amount_mask(const crypto_scalar_t &derivation_scalar)
    {
        SCALAR_NZ_OR_THROW(derivation_scalar);

        scalar_transcript_t transcript(DOMAIN_AMOUNT_MASK_0, derivation_scalar);

        return transcript.challenge();
    }

    crypto_blinding_factor_t generate_commitment_blinding_factor(const crypto_scalar_t &derivation_scalar)
    {
        SCALAR_NZ_OR_THROW(derivation_scalar);

        scalar_transcript_t transcript(DOMAIN_COMMITMENT_MASK_0, derivation_scalar);

        return transcript.challenge();
    }

    crypto_pedersen_commitment_t
        generate_pedersen_commitment(const crypto_scalar_t &blinding_factor, const uint64_t &amount)
    {
        SCALAR_OR_THROW(blinding_factor);

        // r = (amount * H) + (f * G)
        return Crypto::INV_EIGHT * crypto_scalar_t(amount).dbl_mult(Crypto::H, blinding_factor, Crypto::G);
    }

    std::tuple<std::vector<crypto_blinding_factor_t>, std::vector<crypto_pedersen_commitment_t>>
        generate_pseudo_commitments(
            const std::vector<uint64_t> &input_amounts,
            const std::vector<crypto_blinding_factor_t> &output_blinding_factors)
    {
        if (input_amounts.empty() || input_amounts.size() != output_blinding_factors.size())
        {
            throw std::invalid_argument("input_amounts and output_blinding_factors must be non-empty and equal size");
        }

        for (const auto &output_blinding_factor : output_blinding_factors)
        {
            SCALAR_NZ_OR_THROW(output_blinding_factor);
        }

        // tally up the output blinding factors
        const auto sum_of_outputs = crypto_scalar_vector_t(output_blinding_factors).sum();

        // generate a list of random scalars for use as random commitment masks
        auto pseudo_blinding_factors = crypto_scalar_t::random(input_amounts.size());

        // tally up the pseudo blinding factors
        const auto sum_of_pseudo_outputs = crypto_scalar_vector_t(pseudo_blinding_factors).sum();

        std::vector<crypto_pedersen_commitment_t> pseudo_commitments(input_amounts.size());

        for (size_t i = 0; i < input_amounts.size() - 1; i++)
        {
            // generate the pseudo output commitment
            pseudo_commitments[i] = generate_pedersen_commitment(pseudo_blinding_factors[i], input_amounts[i]);
        }

        /**
         * Adds the difference of the output blinding factors minus the pseudo
         * blinding factors to the last blinding factor which then allows us to
         * make sure that the sum of the pseudo outputs equal the sum of the real
         * output blinding factors and thus have validated that the amounts
         * contained within match (THIS DOES NOT PROVE RANGE OF AMOUNTS)
         */
        pseudo_blinding_factors.back() += (sum_of_outputs - sum_of_pseudo_outputs);

        // re-generate the last output commitment
        pseudo_commitments.back() = generate_pedersen_commitment(pseudo_blinding_factors.back(), input_amounts.back());

        // return the vector of pseudo outputs as well the delta of the commitment masks
        return {pseudo_blinding_factors, pseudo_commitments};
    }

    crypto_scalar_t toggle_masked_amount(const crypto_scalar_t &amount_mask, const crypto_scalar_t &amount)
    {
        SCALAR_NZ_OR_THROW(amount_mask);

        SCALAR_NZ_OR_THROW(amount);

        // Truncate to the low 8 bytes (uint64_t range) so the upper 24 bytes
        // remain zero — making masked/unmasked amounts visually distinguishable.
        crypto_scalar_t temp = crypto_scalar_t(amount.to_uint64_t());

        // XOR the amount with the mask (self-inverse: mask XOR mask = identity)
        for (size_t i = 0; i < sizeof(uint64_t); ++i)
        {
            temp[i] ^= amount_mask[i];
        }

        return temp;
    }
} // namespace Crypto::RingCT
