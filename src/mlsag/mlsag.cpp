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
 * @file mlsag.cpp
 * @brief MLSAG (Multilayered Linkable Spontaneous Anonymous Group) ring signatures with optional
 *        Pedersen commitment binding via per-column response scalars.
 */

#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <helpers/constant_time.h>
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/scalar_transcript_t.h>
#include <mlsag/mlsag.h>
#include <stdexcept>

namespace Crypto::RingSignature::MLSAG
{
    // ---- Verify: reconstruct challenge chain and check that it closes back to h0 ----

    bool check_ring_signature(
        const hash_t &message_digest,
        const key_image_t &key_image,
        const std::vector<public_key_t> &public_keys,
        const mlsag_signature_t &signature,
        const std::vector<pedersen_commitment_t> &commitments)
    {
        if (public_keys.empty())
        {
            return false;
        }

        // Strict mode-mismatch reject. The signer's mode is recovered from
        // the signature's own fields (commitment_image, pseudo_commitment, and the presence
        // of per-row commitment_scalars); the caller's stated mode is recovered from the
        // shape of the commitments vector. Disagreement in either direction is a hard reject
        // — no silent downgrade to plain ring mode when commitments are unexpectedly empty,
        // and no silent ignore of caller-supplied commitments against a plain-mode signature.
        // Both directions are caller errors and the verifier surfaces them.
        const bool sig_is_commit_mode =
            (signature.commitment_image.valid() && signature.pseudo_commitment.valid()
             && !signature.commitment_scalars.empty());

        const bool caller_is_commit_mode = !commitments.empty();

        if (sig_is_commit_mode != caller_is_commit_mode)
        {
            return false;
        }

        if (sig_is_commit_mode && commitments.size() != public_keys.size())
        {
            return false;
        }

        const auto use_commitments = sig_is_commit_mode;

        // Reject rings with duplicate public keys
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

        // Key image must be in the prime-order subgroup to prevent small-subgroup attacks
        if (!key_image.check_subgroup())
        {
            return false;
        }

        if (use_commitments && !signature.commitment_image.check_subgroup())
        {
            return false;
        }

        // pseudo_commitment is subtracted from the commitment column of every ring row.
        // valid() (implicit in use_commitments above) only verifies decode/curve membership;
        // it does NOT enforce prime-order subgroup. Reject 8-torsion injection here so the
        // commitment-side L/R reconstruction cannot be tampered with — same threat model as
        // commitment_image (forged-distinct linkability tag → double-spend dedup bypass).
        if (use_commitments && !signature.pseudo_commitment.check_subgroup())
        {
            return false;
        }

        const auto &h0 = signature.challenge;

        std::vector<scalar_t> h(ring_size);

        // ---- Challenge chain: preload shared transcript state, then iterate the ring ----
        // Mode tag fused into the seed flush via the 3-arg constructor so
        // h0 is itself a function of the mode at zero added SHA3 cost. The per-round
        // (L1, R1, L2, R2) updates already differ by mode, but the explicit tag here means
        // a future reader does not have to derive the binding from L/R shape and the
        // runtime mismatch reject above does not stand alone.
        scalar_transcript_t transcript(MLSAG_DOMAIN_0, message_digest, scalar_t(uint64_t(use_commitments ? 1 : 0)));

        transcript.update(public_keys);

        if (use_commitments)
        {
            transcript.update(commitments);

            transcript.update(signature.pseudo_commitment);
        }

        ge_p3 commitment_image_p3 = {};

        if (use_commitments)
        {
            commitment_image_p3 = signature.commitment_image.p3();
        }

        for (size_t i = 0; i < ring_size; i++)
        {
            auto temp_h = h[i];

            if (i == 0)
            {
                temp_h = h0;
            }

            // HP = [Hp(P[i])] mod l
            const auto HP = hash_t::sha3(public_keys[i]).point();

            // Column 1 (key): L1 = s1[i] * G + h * P[i], R1 = s1[i] * HP + h * I
            const auto L1 = temp_h.dbl_mult(public_keys[i], signature.key_scalars[i], Crypto::G);

            const auto R1 = signature.key_scalars[i].dbl_mult(HP, temp_h, key_image);

            if (use_commitments)
            {
                // C_diff = EIGHT * (C[i] - pseudo_commitment)
                const auto C_diff = Crypto::EIGHT * (commitments[i] - signature.pseudo_commitment);

                // Column 2 (commitment): L2 = s2[i] * G + h * C_diff, R2 = s2[i] * HP + h * D
                const auto L2 = temp_h.dbl_mult(C_diff, signature.commitment_scalars[i], Crypto::G);

                const auto R2 = signature.commitment_scalars[i].dbl_mult(HP, temp_h, signature.commitment_image);

                auto sub_transcript = transcript;

                sub_transcript.update(L1, R1);

                sub_transcript.update(L2, R2);

                const auto challenge = sub_transcript.challenge();

                if (!challenge.valid())
                {
                    return false;
                }

                h[(i + 1) % ring_size] = challenge;
            }
            else
            {
                auto sub_transcript = transcript;

                sub_transcript.update(L1, R1);

                const auto challenge = sub_transcript.challenge();

                if (!challenge.valid())
                {
                    return false;
                }

                h[(i + 1) % ring_size] = challenge;
            }
        }

        // The ring closes iff the recomputed chain returns to the initial challenge
        return h[0] == h0;
    }

    // ---- Sign (auto-detect signer index): find our key in the ring, then delegate ----

    std::tuple<bool, mlsag_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys,
        const blinding_factor_t &input_blinding_factor,
        const std::vector<pedersen_commitment_t> &public_commitments,
        const blinding_factor_t &pseudo_blinding_factor,
        const pedersen_commitment_t &pseudo_commitment)
    {
        if (!secret_ephemeral.valid())
        {
            return {false, {}};
        }

        // Strict mode-mismatch reject on the sign side. Either the caller
        // supplies all four commitment-mode arguments (input_blinding_factor,
        // pseudo_blinding_factor, pseudo_commitment, and a public_commitments vector
        // matching the ring size) or none of them. Partial supply is a caller error and
        // is rejected here rather than silently dropping into plain mode — the symmetric
        // case to the verifier-side mismatch check.
        const bool any_commit_field_supplied =
            (input_blinding_factor.valid() || pseudo_blinding_factor.valid() || pseudo_commitment.valid()
             || !public_commitments.empty());

        const bool all_commit_fields_supplied =
            (input_blinding_factor.valid() && pseudo_blinding_factor.valid() && pseudo_commitment.valid()
             && public_commitments.size() == public_keys.size());

        if (any_commit_field_supplied && !all_commit_fields_supplied)
        {
            return {false, {}};
        }

        const auto use_commitments = all_commit_fields_supplied;

        const auto ring_size = public_keys.size();

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * Crypto::G;

        // constant-time scan: check all elements, count matches
        size_t real_output_index = ring_size; // sentinel
        size_t match_count = 0;

        for (size_t i = 0; i < ring_size; i++)
        {
            bool match;

            if (use_commitments)
            {
                const auto public_commitment = (input_blinding_factor - pseudo_blinding_factor) * Crypto::G;

                const auto derived_commitment = Crypto::EIGHT * (public_commitments[i] - pseudo_commitment);

                match = (public_ephemeral == public_keys[i] && public_commitment == derived_commitment);
            }
            else
            {
                match = (public_ephemeral == public_keys[i]);
            }

            // SECURITY: constant-time conditional update to avoid leaking signer index
            real_output_index = constant_time_select(match, i, real_output_index);
            match_count += static_cast<size_t>(match);
        }

        if (match_count != 1)
        {
            return {false, {}};
        }

        return generate_ring_signature(
            message_digest,
            secret_ephemeral,
            public_keys,
            real_output_index,
            input_blinding_factor,
            public_commitments,
            pseudo_blinding_factor,
            pseudo_commitment);
    }

    // ---- Sign (explicit signer index): inlined MLSAG construction ----

    std::tuple<bool, mlsag_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys,
        size_t real_output_index,
        const blinding_factor_t &input_blinding_factor,
        const std::vector<pedersen_commitment_t> &public_commitments,
        const blinding_factor_t &pseudo_blinding_factor,
        const pedersen_commitment_t &pseudo_commitment)
    {
        if (!secret_ephemeral.valid())
        {
            return {false, {}};
        }

        // Reject rings with duplicate public keys
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return {false, {}};
            }
        }

        // Same strict mode-mismatch reject as the auto-detect overload —
        // both sign entry points must enforce identical caller-arguments preconditions so
        // a downstream signer cannot accidentally route around the check by going through
        // the explicit-index path.
        const bool any_commit_field_supplied =
            (input_blinding_factor.valid() || pseudo_blinding_factor.valid() || pseudo_commitment.valid()
             || !public_commitments.empty());

        const bool all_commit_fields_supplied =
            (input_blinding_factor.valid() && pseudo_blinding_factor.valid() && pseudo_commitment.valid()
             && public_commitments.size() == public_keys.size());

        if (any_commit_field_supplied && !all_commit_fields_supplied)
        {
            return {false, {}};
        }

        const auto use_commitments = all_commit_fields_supplied;

        const auto ring_size = public_keys.size();

        if (real_output_index >= ring_size)
        {
            return {false, {}};
        }

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * Crypto::G;

        if (public_ephemeral != public_keys[real_output_index])
        {
            return {false, {}};
        }

        // blinding scalar difference for commitments
        const auto z = input_blinding_factor - pseudo_blinding_factor;

        if (use_commitments)
        {
            const auto commitment = Crypto::EIGHT * (public_commitments[real_output_index] - pseudo_commitment);

            // sanity check: z * G should match the commitment difference
            if (commitment != z * Crypto::G)
            {
                return {false, {}};
            }
        }

        // validate uniqueness (defense-in-depth)
        size_t match_count = 0;

        for (size_t i = 0; i < ring_size; i++)
        {
            if (public_ephemeral == public_keys[i])
            {
                ++match_count;
            }
        }

        if (match_count != 1)
        {
            return {false, {}};
        }

        // compute HP for the real output once — reused for key image, commitment image, and signing
        const auto HP_real = hash_t::sha3(public_keys[real_output_index]).point();

        // generate key image: I = [Hp(P) * x] mod l
        const auto key_image = secret_ephemeral * HP_real;

        key_image_t commitment_image;

        if (use_commitments)
        {
            // commitment image uses the same HP as the key image
            commitment_image = z * HP_real;
        }

    try_again:
        // ---- Generate nonces and random decoy scalars ----
        // alpha1: nonce for key column, derived from message/key_image/randomness
        scalar_transcript_t alpha1_transcript(message_digest, key_image, scalar_t::random());

        alpha1_transcript.update(input_blinding_factor, pseudo_blinding_factor, pseudo_commitment);

        alpha1_transcript.update(public_commitments);

        const auto alpha1 = alpha1_transcript.challenge();

        if (!alpha1.valid())
        {
            goto try_again;
        }

        // alpha2: independent nonce for commitment column (different domain to prevent nonce reuse)
        scalar_t alpha2;

        if (use_commitments)
        {
            scalar_transcript_t alpha2_transcript(MLSAG_DOMAIN_1, commitment_image, scalar_t::random());

            alpha2_transcript.update(input_blinding_factor, pseudo_blinding_factor, pseudo_commitment);

            alpha2_transcript.update(public_commitments);

            alpha2 = alpha2_transcript.challenge();

            if (!alpha2.valid())
            {
                goto try_again;
            }
        }

        auto s1 = scalar_t::random(ring_size);

        std::vector<scalar_t> s2;

        if (use_commitments)
        {
            s2 = scalar_t::random(ring_size);
        }

        std::vector<scalar_t> h(ring_size);

        // ---- Build challenge chain starting from the real signer ----
        // Mode tag fused into the seed flush — must match the verifier's
        // tag at the same position. Belt-and-suspenders to the strict mismatch reject
        // above; the mode the signer chose is part of h0 itself, not just an artefact of
        // L/R shape.
        scalar_transcript_t transcript(MLSAG_DOMAIN_0, message_digest, scalar_t(uint64_t(use_commitments ? 1 : 0)));

        transcript.update(public_keys);

        if (use_commitments)
        {
            transcript.update(public_commitments);

            transcript.update(pseudo_commitment);
        }

        // Real input: use alpha nonces for L/R points
        {
            // L1 = alpha1 * G
            const auto L1 = alpha1 * G;

            // R1 = alpha1 * HP_real
            const auto R1 = alpha1 * HP_real;

            auto sub_transcript = transcript;

            sub_transcript.update(L1, R1);

            if (use_commitments)
            {
                // L2 = alpha2 * G
                const auto L2 = alpha2 * G;

                // R2 = alpha2 * HP_real
                const auto R2 = alpha2 * HP_real;

                sub_transcript.update(L2, R2);
            }

            const auto challenge = sub_transcript.challenge();

            if (!challenge.valid())
            {
                goto try_again;
            }

            h[(real_output_index + 1) % ring_size] = challenge;
        }

        // Propagate the challenge chain through all decoy members
        if (ring_size > 1)
        {
            ge_p3 commitment_image_p3 = {};

            if (use_commitments)
            {
                commitment_image_p3 = commitment_image.p3();
            }

            for (size_t i = real_output_index + 1; i < real_output_index + ring_size; i++)
            {
                const auto idx = i % ring_size;

                // HP = [Hp(P[idx])] mod l
                const auto HP = hash_t::sha3(public_keys[idx]).point();

                // Column 1: L1 = s1[idx] * G + h * P[idx], R1 = s1[idx] * HP + h * I
                const auto L1 = h[idx].dbl_mult(public_keys[idx], s1[idx], Crypto::G);

                const auto R1 = s1[idx].dbl_mult(HP, h[idx], key_image);

                auto sub_transcript = transcript;

                sub_transcript.update(L1, R1);

                if (use_commitments)
                {
                    // C_diff = EIGHT * (C[idx] - pseudo_commitment)
                    const auto C_diff = Crypto::EIGHT * (public_commitments[idx] - pseudo_commitment);

                    // Column 2: L2 = s2[idx] * G + h * C_diff, R2 = s2[idx] * HP + h * D
                    const auto L2 = h[idx].dbl_mult(C_diff, s2[idx], Crypto::G);

                    const auto R2 = s2[idx].dbl_mult(HP, h[idx], commitment_image);

                    sub_transcript.update(L2, R2);
                }

                const auto challenge = sub_transcript.challenge();

                if (!challenge.valid())
                {
                    return {false, {}};
                }

                h[(idx + 1) % ring_size] = challenge;
            }
        }

        // ---- Close the ring: compute real signer's response scalars ----
        // s1[real] = alpha1 - h[real] * x
        s1[real_output_index] = alpha1 - h[real_output_index] * secret_ephemeral;

        // s2[real] = alpha2 - h[real] * z
        if (use_commitments)
        {
            s2[real_output_index] = alpha2 - h[real_output_index] * z;
        }

        return {true, mlsag_signature_t(std::move(s1), std::move(s2), h[0], commitment_image, pseudo_commitment)};
    }
} // namespace Crypto::RingSignature::MLSAG
