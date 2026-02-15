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
// Inspired by the work of Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/clsag

/**
 * @file ring_signature_clsag.cpp
 * @brief CLSAG (Compact Linkable Spontaneous Anonymous Group) ring signatures with optional
 *        Pedersen commitment binding via mu_P/mu_C aggregation coefficients.
 */

#include <crypto_constants.h>
#include <cstring>
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/scalar_transcript_t.h>
#include <signatures/ring_signature_clsag.h>

namespace Crypto::RingSignature::CLSAG
{
    // ---- Verify: reconstruct challenge chain and check that it closes back to h0 ----

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

        const auto &h0 = signature.challenge;

        std::vector<crypto_scalar_t> h(ring_size);

        // ---- Compute aggregation coefficients mu_P and mu_C ----
        // mu_P weights the public key component; mu_C weights the commitment component.
        // Both are derived from domain-separated transcripts binding the ring and key image.

        crypto_scalar_t mu_P, mu_C;

        // mu_P: aggregation weight for public key terms
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
                return false;
            }
        }

        // mu_C: aggregation weight for commitment terms (different domain separator)
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
                return false;
            }
        }

        // ---- Challenge chain: preload shared transcript state, then iterate the ring ----
        // The base transcript (domain, message, keys, commitments) is constant across rounds;
        // each round forks a copy and appends its own (L, R) before hashing.
        scalar_transcript_t transcript(CLSAG_DOMAIN_1, message_digest);

        transcript.update(public_keys);

        if (use_commitments)
        {
            transcript.update(commitments);

            transcript.update(signature.pseudo_commitment);
        }

        // Cache ge_p3 representations outside the loop (constant across iterations)
        const auto key_image_p3 = key_image.p3();

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

            const auto idx = i % ring_size;

            // r = (temp_h * mu_P) mod l
            const auto r = temp_h * mu_P;

            // HP = [Hp(P[idx])] mod l
            const auto HP = crypto_hash_t::sha3(public_keys[idx]).point();

            crypto_point_t L, R;

            if (use_commitments)
            {
                // r2 = (temp_h * mu_C) mod l
                const auto r2 = temp_h * mu_C;

                // C = (C[idx] - PS) mod l
                const auto C = Crypto::EIGHT * (commitments[idx] - signature.pseudo_commitment);

                // L = s[idx] * G + r * P[idx] + r2 * C
                {
                    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                    unsigned char scalars[2 * 32];
                    ge_p3 points[2];

                    std::memcpy(&scalars[0], r.data(), 32);
                    points[0] = public_keys[idx].p3();
                    std::memcpy(&scalars[32], r2.data(), 32);
                    points[1] = C.p3();

                    ge_multiscalar_mul_base_vartime(&result, scalars, points, 2, signature.scalars[idx].data());

                    L = crypto_point_t(result);
                }

                // R = s[idx] * HP + r * I + r2 * D
                {
                    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                    unsigned char scalars[3 * 32];
                    ge_p3 points[3];

                    std::memcpy(&scalars[0], signature.scalars[idx].data(), 32);
                    points[0] = HP.p3();
                    std::memcpy(&scalars[32], r.data(), 32);
                    points[1] = key_image_p3;
                    std::memcpy(&scalars[64], r2.data(), 32);
                    points[2] = commitment_image_p3;

                    ge_multiscalar_mul_vartime(&result, scalars, points, 3);

                    R = crypto_point_t(result);
                }
            }
            else
            {
                // L = [(r * P[idx]) + (s[idx] * G)] mod l
                L = r.dbl_mult(public_keys[idx], signature.scalars[idx], Crypto::G);

                // R = [(s[idx] * HP) + (r * I)] mod l
                R = signature.scalars[idx].dbl_mult(HP, r, key_image);
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

        // The ring closes iff the recomputed chain returns to the initial challenge
        return h[0] == h0;
    }

    // ---- Sign (auto-detect signer index): find our key in the ring, then delegate ----

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

        const auto use_commitments =
            (input_blinding_factor.valid() && public_commitments.size() == public_keys.size()
             && pseudo_blinding_factor.valid() && pseudo_commitment.valid());

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

            if (match)
            {
                real_output_index = i;
                ++match_count;
            }
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

    // ---- Sign (explicit signer index): inlined CLSAG construction ----

    std::tuple<bool, crypto_clsag_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &public_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
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

        const auto use_commitments =
            (input_blinding_factor.valid() && public_commitments.size() == public_keys.size()
             && pseudo_blinding_factor.valid() && pseudo_commitment.valid());

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

        if (use_commitments)
        {
            const auto public_commitment = (input_blinding_factor - pseudo_blinding_factor) * Crypto::G;

            const auto derived_commitment = Crypto::EIGHT * (public_commitments[real_output_index] - pseudo_commitment);

            if (public_commitment != derived_commitment)
            {
                return {false, {}};
            }
        }

        // validate uniqueness (defense-in-depth — dedupe_and_sort_keys already rejects duplicates)
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
        const auto HP_real = crypto_hash_t::sha3(public_keys[real_output_index]).point();

        // generate key image: I = [Hp(P) * x] mod l
        const auto key_image = secret_ephemeral * HP_real;

        // blinding scalar difference for commitments
        const auto z = input_blinding_factor - pseudo_blinding_factor;

        crypto_key_image_t commitment_image;

        if (use_commitments)
        {
            const auto commitment = Crypto::EIGHT * (public_commitments[real_output_index] - pseudo_commitment);

            // sanity check: z * G should match the commitment difference
            if (commitment != z * Crypto::G)
            {
                return {false, {}};
            }

            // commitment image uses the same HP as the key image
            commitment_image = z * HP_real;
        }

    try_again:
        // ---- Generate nonce and random decoy scalars ----
        // Derive nonce by hashing message, key image, commitments, and fresh randomness
        scalar_transcript_t alpha_transcript(message_digest, key_image, crypto_scalar_t::random());

        alpha_transcript.update(input_blinding_factor, pseudo_blinding_factor, pseudo_commitment);

        alpha_transcript.update(public_commitments);

        const auto alpha_scalar = alpha_transcript.challenge();

        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        auto signature = crypto_scalar_t::random(ring_size);

        std::vector<crypto_scalar_t> h(ring_size);

        // ---- Compute aggregation coefficients (must match verifier's computation) ----
        crypto_scalar_t mu_P, mu_C;

        // mu_P: aggregation weight for public key terms
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
                return {false, {}};
            }
        }

        // mu_C: aggregation weight for commitment terms
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
                return {false, {}};
            }
        }

        // ---- Build challenge chain starting from the real signer ----
        // Preload shared transcript state; each round forks a copy and appends (L, R).
        scalar_transcript_t transcript(CLSAG_DOMAIN_1, message_digest);

        transcript.update(public_keys);

        if (use_commitments)
        {
            transcript.update(public_commitments);

            transcript.update(pseudo_commitment);
        }

        // Real input: use alpha nonce for commitment points (L, R)
        {
            // L = (a * G) mod l;
            const auto L = alpha_scalar * G;

            // R = (alpha * HP) mod l — reuse precomputed HP_real
            const auto R = alpha_scalar * HP_real;

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

        // Propagate the challenge chain through all decoy members
        if (ring_size > 1)
        {
            // Cache ge_p3 representations outside the loop
            const auto key_image_p3 = key_image.p3();

            ge_p3 commitment_image_p3 = {};

            if (use_commitments)
            {
                commitment_image_p3 = commitment_image.p3();
            }

            for (size_t i = real_output_index + 1; i < real_output_index + ring_size; i++)
            {
                const auto idx = i % ring_size;

                // r = (h[idx] * mu_P) mod l
                const auto r = h[idx] * mu_P;

                // HP = [Hp(P)] mod l
                const auto HP = crypto_hash_t::sha3(public_keys[idx]).point();

                crypto_point_t L, R;

                if (use_commitments)
                {
                    // r2 = (h[idx] * mu_C) mod l
                    const auto r2 = h[idx] * mu_C;

                    // C = (C[idx] - PS) mod l
                    const auto C = Crypto::EIGHT * (public_commitments[idx] - pseudo_commitment);

                    // L = s[idx] * G + r * P[idx] + r2 * C
                    {
                        ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                        unsigned char scalars[2 * 32];
                        ge_p3 points[2];

                        std::memcpy(&scalars[0], r.data(), 32);
                        points[0] = public_keys[idx].p3();
                        std::memcpy(&scalars[32], r2.data(), 32);
                        points[1] = C.p3();

                        ge_multiscalar_mul_base_vartime(&result, scalars, points, 2, signature[idx].data());

                        L = crypto_point_t(result);
                    }

                    // R = s[idx] * HP + r * I + r2 * D
                    {
                        ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                        unsigned char scalars[3 * 32];
                        ge_p3 points[3];

                        std::memcpy(&scalars[0], signature[idx].data(), 32);
                        points[0] = HP.p3();
                        std::memcpy(&scalars[32], r.data(), 32);
                        points[1] = key_image_p3;
                        std::memcpy(&scalars[64], r2.data(), 32);
                        points[2] = commitment_image_p3;

                        ge_multiscalar_mul_vartime(&result, scalars, points, 3);

                        R = crypto_point_t(result);
                    }
                }
                else
                {
                    // L = [(r * P) + (s[idx] * G)] mod l
                    L = r.dbl_mult(public_keys[idx], signature[idx], Crypto::G);

                    // R = [(s[idx] * HP) + (r * I)] mod l
                    R = signature[idx].dbl_mult(HP, r, key_image);
                }

                auto sub_transcript = transcript;

                sub_transcript.update(L, R);

                const auto challenge = sub_transcript.challenge();

                if (!challenge.valid())
                {
                    return {false, {}};
                }

                h[(idx + 1) % ring_size] = challenge;
            }
        }

        // ---- Close the ring: compute real signer's response scalar ----
        // s_real = alpha - h_real * (mu_P * x + mu_C * z)
        signature[real_output_index] = alpha_scalar;

        signature[real_output_index] -= (h[real_output_index] * (mu_P * secret_ephemeral));

        if (use_commitments)
        {
            signature[real_output_index] -= (h[real_output_index] * z * mu_C);
        }

        return {true, crypto_clsag_signature_t(signature, h[0], commitment_image, pseudo_commitment)};
    }
} // namespace Crypto::RingSignature::CLSAG
