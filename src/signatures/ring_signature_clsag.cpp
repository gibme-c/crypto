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
// Inspired by the work of Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/clsag

#include <crypto_constants.h>
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/scalar_transcript_t.h>
#include <signatures/ring_signature_clsag.h>

namespace Crypto::RingSignature::CLSAG
{
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_clsag_signature_t &signature,
        const std::vector<crypto_pedersen_commitment_t> &commitments)
    {
        const auto use_commitments =
            (signature.commitment_image.valid() && commitments.size() == public_keys.size()
             && signature.pseudo_commitment.valid());

        // check to verify that there are no duplicate keys in the set
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return false;
            }
        }

        const auto ring_size = public_keys.size();

        if (!signature.check_construction(ring_size, use_commitments))
        {
            return false;
        }

        if (!key_image.check_subgroup())
        {
            return false;
        }

        const auto &h0 = signature.challenge;

        // the computational hash vector is only as big as our ring (not including the check hash)
        std::vector<crypto_scalar_t> h(ring_size);

        crypto_scalar_t mu_P, mu_C;

        // generate mu_P
        {
            scalar_transcript_t transcript(CLSAG_DOMAIN_0, key_image);

            transcript.update(public_keys);

            if (use_commitments)
            {
                transcript.update(signature.commitment_image);

                transcript.update(commitments);

                transcript.update(signature.pseudo_commitment);
            }

            mu_P = transcript.challenge();

            if (!mu_P.valid())
            {
                // our mu_P cannot be 0
                return false;
            }
        }

        // generate mu_C
        if (use_commitments)
        {
            scalar_transcript_t transcript(CLSAG_DOMAIN_2, key_image);

            transcript.update(public_keys);

            transcript.update(signature.commitment_image);

            transcript.update(commitments);

            transcript.update(signature.pseudo_commitment);

            mu_C = transcript.challenge();

            if (!mu_C.valid())
            {
                // our mu_C cannot be 0
                return false;
            }
        }

        /**
         * This transcript is the same for each round so re-computing the state of the
         * transcript for each round is a waste of processing power, instead we'll
         * preload this information and make a copy of the state before we use it
         * for each round's computation
         */
        scalar_transcript_t transcript(CLSAG_DOMAIN_1, message_digest);

        transcript.update(public_keys);

        if (use_commitments)
        {
            transcript.update(commitments);

            transcript.update(signature.pseudo_commitment);
        }

        for (size_t i = 0; i < ring_size; i++)
        {
            auto temp_h = h[i];

            if (i == 0)
            {
                temp_h = h0;
            }

            const auto idx = i % ring_size;

            // r = (temp_h * mu_P) mod l
            const auto r = temp_h * mu_P;

            // L = [(r * P[idx]) + (s[idx] * G)] mod l
            auto L = r.dbl_mult(public_keys[idx], signature.scalars[idx], Crypto::G);

            // HP = [Hp(P[idx])] mod l
            const auto HP = crypto_hash_t::sha3(public_keys[idx]).point();

            // R = [(s[idx] * HP) + (r * I)] mod l
            auto R = signature.scalars[idx].dbl_mult(HP, r, key_image);

            if (use_commitments)
            {
                // r2 = (temp_h * mu_C) mod l
                const auto r2 = temp_h * mu_C;

                /**
                 * Here we're calculating the offset commitments based upon the input
                 * commitments minus the pseudo commitment that was provided thus
                 * allowing us to verify their signers knowledge of z (the delta between the
                 * input blinding scalar and the pseudo blinding scalar) while committing
                 * to a "zero" amount difference between the two commitments
                 */
                // C = (C[idx] - PS) mod l
                const auto C = Crypto::EIGHT * (commitments[idx] - signature.pseudo_commitment);

                // L += [r2 * (C[idx] - PS)] mod l
                L += (r2 * C);

                // R += (r2 * D) mod l
                R += (r2 * signature.commitment_image);
            }

            auto sub_transcript = transcript;

            sub_transcript.update(L, R);

            const auto challenge = sub_transcript.challenge();

            // The challenge value should never be 0
            if (!challenge.valid())
            {
                return false;
            }

            h[(i + 1) % ring_size] = challenge;
        }

        return h[0] == h0;
    }

    std::tuple<bool, crypto_clsag_signature_t> complete_ring_signature(
        const crypto_scalar_t &signing_scalar,
        size_t real_output_index,
        const crypto_clsag_signature_t &signature,
        const std::vector<crypto_scalar_t> &h,
        const crypto_scalar_t &mu_P)
    {
        if (signature.scalars.empty() || real_output_index >= signature.scalars.size()
            || h.size() != signature.scalars.size())
        {
            return {false, {}};
        }

        if (!signing_scalar.valid() || !signature.challenge.valid() || !mu_P.valid())
        {
            return {false, {}};
        }

        for (const auto &scalar : signature.scalars)
        {
            if (!scalar.valid())
            {
                return {false, {}};
            }
        }

        for (const auto &scalar : h)
        {
            if (!scalar.valid())
            {
                return {false, {}};
            }
        }

        std::vector<crypto_scalar_t> finalized_signature(signature.scalars);

        // s = [alpha - (h[real_output_index] * (p * mu_P))] mod l
        finalized_signature[real_output_index] -= (h[real_output_index] * (mu_P * signing_scalar));

        return {
            true,
            crypto_clsag_signature_t(
                finalized_signature, signature.challenge, signature.commitment_image, signature.pseudo_commitment)};
    }

    std::tuple<bool, crypto_clsag_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &public_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
    {
        if (!secret_ephemeral.valid())
        {
            return {false, {}};
        }

        // check to verify that there are no duplicate keys in the set
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return {false, {}};
            }
        }

        const auto use_commitments =
            (input_blinding_factor.valid() && public_commitments.size() == public_keys.size()
             && pseudo_blinding_factor.valid() && pseudo_commitment.valid());

        const auto ring_size = public_keys.size();

        // find our real input in the list
        size_t real_output_index = -1;

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * Crypto::G;

        /**
         * Look for a public_ephemeral in the key set that we have the
         * secret ephemeral for
         */
        for (size_t i = 0; i < ring_size; i++)
        {
            if (use_commitments)
            {
                if (!input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
                {
                    return {false, {}};
                }

                const auto public_commitment = (input_blinding_factor - pseudo_blinding_factor) * Crypto::G;

                const auto derived_commitment = Crypto::EIGHT * (public_commitments[i] - pseudo_commitment);

                if (public_ephemeral == public_keys[i] && public_commitment == derived_commitment)
                {
                    real_output_index = i;

                    break;
                }
            }
            else
            {
                if (public_ephemeral == public_keys[i])
                {
                    real_output_index = i;

                    break;
                }
            }
        }

        /**
         * if we could not find the related public key(s) in the list or the proper
         * commitments provided, then fail as we cannot generate a valid signature
         */
        if (real_output_index == -1)
        {
            return {false, {}};
        }

        const auto key_image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

        const auto [prep_success, signature, h, mu_P] = prepare_ring_signature(
            message_digest,
            key_image,
            public_keys,
            real_output_index,
            input_blinding_factor,
            public_commitments,
            pseudo_blinding_factor,
            pseudo_commitment);

        if (!prep_success)
        {
            return {false, {}};
        }

        return complete_ring_signature(secret_ephemeral, real_output_index, signature, h, mu_P);
    }

    std::tuple<bool, crypto_clsag_signature_t, std::vector<crypto_scalar_t>, crypto_scalar_t> prepare_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &public_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
    {
        // check to verify that there are no duplicate keys in the set
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return {false, {}, {}, {}};
            }
        }

        const auto ring_size = public_keys.size();

        const auto use_commitments =
            (input_blinding_factor.valid() && public_commitments.size() == public_keys.size()
             && pseudo_blinding_factor.valid() && pseudo_commitment.valid());

        if (real_output_index >= ring_size)
        {
            return {false, {}, {}, {}};
        }

        if (!key_image.check_subgroup())
        {
            return {false, {}, {}, {}};
        }

    try_again:
        // help to provide stronger RNG for the alpha scalar
        scalar_transcript_t alpha_transcript(message_digest, key_image, crypto_scalar_t::random());

        alpha_transcript.update(input_blinding_factor, pseudo_blinding_factor, pseudo_commitment);

        alpha_transcript.update(public_commitments);

        const auto alpha_scalar = alpha_transcript.challenge();

        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        auto signature = crypto_scalar_t::random(ring_size);

        // See below for more detail
        const auto z = input_blinding_factor - pseudo_blinding_factor;

        crypto_key_image_t commitment_image;

        if (use_commitments)
        {
            if (!input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
            {
                return {false, {}, {}, {}};
            }

            /**
             * TLDR: If we know the difference between the input blinding scalar and the
             * pseudo output blinding scalar then we can use that difference as the secret
             * key for the difference between the input commitment and the pseudo commitment
             * thus providing no amount component differences in the commitments between the
             * two and hence we are committing (in a non-revealing way) that the pseudo output
             * commitment is equivalent to ONE of the input commitments in the set
             */
            const auto commitment = Crypto::EIGHT * (public_commitments[real_output_index] - pseudo_commitment);

            /**
             * Quick sanity check to make sure that the computed z value (blinding scalar) delta
             * has a resulting public point that is the same as the commitment that we can sign for above
             */
            if (commitment != z * Crypto::G)
            {
                return {false, {}, {}, {}};
            }

            /**
             * This likely looks a bit goofy; however, the commitment image is based upon
             * the public output key not the commitment point to prevent a whole bunch
             * of frivolous math that only makes this far worse later
             */
            commitment_image = Crypto::generate_key_image(public_keys[real_output_index], z);
        }

        std::vector<crypto_scalar_t> h(ring_size);

        crypto_scalar_t mu_P, mu_C;

        // generate mu_P
        {
            scalar_transcript_t transcript(CLSAG_DOMAIN_0, key_image);

            transcript.update(public_keys);

            if (use_commitments)
            {
                transcript.update(commitment_image);

                transcript.update(public_commitments);

                transcript.update(pseudo_commitment);
            }

            mu_P = transcript.challenge();

            if (!mu_P.valid())
            {
                // We exit here as trying again does not change the transcript inputs
                return {false, {}, {}, {}};
            }
        }

        // generate mu_C
        if (use_commitments)
        {
            scalar_transcript_t transcript(CLSAG_DOMAIN_2, key_image);

            transcript.update(public_keys);

            transcript.update(commitment_image);

            transcript.update(public_commitments);

            transcript.update(pseudo_commitment);

            mu_C = transcript.challenge();

            if (!mu_C.valid())
            {
                // We exit here as trying again does not change the transcript inputs
                return {false, {}, {}, {}};
            }
        }

        /**
         * This transcript is the same for each round so re-computing the state of the
         * transcript for each round is a waste of processing power, instead we'll
         * preload this information and make a copy of the state before we use it
         * for each round's computation
         */
        scalar_transcript_t transcript(CLSAG_DOMAIN_1, message_digest);

        transcript.update(public_keys);

        if (use_commitments)
        {
            transcript.update(public_commitments);

            transcript.update(pseudo_commitment);
        }

        // real input
        {
            // L = (a * G) mod l;
            const auto L = alpha_scalar * G;

            // HP = [Hp(P)] mod l
            const auto HP = crypto_hash_t::sha3(public_keys[real_output_index]).point();

            // R = (alpha * HP) mod l
            const auto R = alpha_scalar * HP;

            auto sub_transcript = transcript;

            sub_transcript.update(L, R);

            const auto challenge = sub_transcript.challenge();

            // our challenge value should never be 0
            if (!challenge.valid())
            {
                goto try_again;
            }

            h[(real_output_index + 1) % ring_size] = challenge;
        }

        if (ring_size > 1)
        {
            for (size_t i = real_output_index + 1; i < real_output_index + ring_size; i++)
            {
                const auto idx = i % ring_size;

                // r = (h[idx] * mu_P) mod l
                const auto r = h[idx] * mu_P;

                // L = [(r * P) + (s[idx] * G)] mod l
                auto L = r.dbl_mult(public_keys[idx], signature[idx], Crypto::G);

                // HP = [Hp(P)] mod l
                const auto HP = crypto_hash_t::sha3(public_keys[idx]).point();

                // R = [(s[idx] * HP) + (r * I)] mod l
                auto R = signature[idx].dbl_mult(HP, r, key_image);

                if (use_commitments)
                {
                    // r2 = (h[idx] * mu_C) mod l
                    const auto r2 = h[idx] * mu_C;

                    /**
                     * Here we're calculating the offset commitments based upon the input
                     * commitments minus our pseudo commitment that we generated thus
                     * allowing us to prove our knowledge of z (the delta between the
                     * input blinding scalar and the pseudo blinding scalar) while committing
                     * to a "zero" amount difference between the two commitments
                     */
                    // C = (C[idx] - PS) mod l
                    const auto C = Crypto::EIGHT * (public_commitments[idx] - pseudo_commitment);

                    // L += (r2 * C[idx]) mod l
                    L += (r2 * C);

                    // R += (r2 * D) mod l
                    R += (r2 * commitment_image);
                }

                auto sub_transcript = transcript;

                sub_transcript.update(L, R);

                const auto challenge = sub_transcript.challenge();

                /*
                 * our challenge value should never be 0
                 *
                 * As this challenge value does not have a random component, if we fail this check here
                 * then we need to fail out totally instead of trying again as the transcript value will
                 * not change just by trying again
                 */
                if (!challenge.valid())
                {
                    return {false, {}, {}, {}};
                }

                h[(idx + 1) % ring_size] = challenge;
            }
        }

        signature[real_output_index] = alpha_scalar;

        if (use_commitments)
        {
            signature[real_output_index] -= (h[real_output_index] * z * mu_C);
        }

        return {true, crypto_clsag_signature_t(signature, h[0], commitment_image, pseudo_commitment), h, mu_P};
    }
} // namespace Crypto::RingSignature::CLSAG
