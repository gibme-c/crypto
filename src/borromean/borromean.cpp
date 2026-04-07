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
 * @file borromean.cpp
 * @brief Borromean ring signatures with key image linkability for signer anonymity within a ring.
 */

#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <helpers/constant_time.h>
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/scalar_transcript_t.h>
#include <borromean/borromean.h>
#include <stdexcept>

namespace Crypto::RingSignature::Borromean
{
    // ---- Verify: reconstruct per-member (L, R) pairs and check challenge sum ----

    bool check_ring_signature(
        const hash_t &message_digest,
        const key_image_t &key_image,
        const std::vector<public_key_t> &public_keys,
        const borromean_signature_t &borromean_signature)
    {
        if (public_keys.empty())
        {
            return false;
        }

        // Reject rings with duplicate public keys (prevents trivial forgery)
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return false;
            }
        }

        const auto ring_size = public_keys.size();

        if (!borromean_signature.check_construction(ring_size))
        {
            return false;
        }

        const auto &signature = borromean_signature.signatures;

        if (!key_image.check_subgroup())
        {
            return false;
        }

        // Accumulate per-member challenge scalars and reconstruct (L, R) commitment pairs
        scalar_t sum;

        scalar_transcript_t transcript(BORROMEAN_DOMAIN_0, message_digest);

        for (size_t i = 0; i < ring_size; i++)
        {
            // HP = Hp(P_i) — hash-to-point for key image linkability
            const auto HP = hash_t::sha3(public_keys[i]).point();

            // L_i = c_i*P_i + r_i*G
            const auto L = signature[i].LR.L.dbl_mult(public_keys[i], signature[i].LR.R, Crypto::G);

            // R_i = r_i*Hp(P_i) + c_i*I
            const auto R = signature[i].LR.R.dbl_mult(HP, signature[i].LR.L, key_image);

            sum += signature[i].LR.L;

            transcript.update(L, R);
        }

        const auto challenge = transcript.challenge();

        if (!challenge.valid())
        {
            return false;
        }

        // Valid iff the sum of per-member challenges equals the recomputed aggregate challenge
        return !(challenge - sum).is_nonzero();
    }

    // ---- Sign (auto-detect signer index): find our key in the ring, then delegate ----

    std::tuple<bool, borromean_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys)
    {
        if (!secret_ephemeral.valid())
        {
            return {false, {}};
        }

        const auto ring_size = public_keys.size();

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * G;

        // constant-time scan: check all elements, count matches.
        // Uses conditional-move to update the index without branching on match.
        size_t real_output_index = ring_size; // sentinel
        size_t match_count = 0;

        for (size_t i = 0; i < ring_size; i++)
        {
            const bool match = (public_ephemeral == public_keys[i]);

            // SECURITY: constant-time conditional update to avoid leaking signer index
            real_output_index = constant_time_select(match, i, real_output_index);
            match_count += static_cast<size_t>(match);
        }

        if (match_count != 1)
        {
            return {false, {}};
        }

        return generate_ring_signature(message_digest, secret_ephemeral, public_keys, real_output_index);
    }

    // ---- Sign (explicit signer index): inlined Borromean construction (no prepare/complete split) ----

    std::tuple<bool, borromean_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys,
        size_t real_output_index)
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

        const auto ring_size = public_keys.size();

        if (real_output_index >= ring_size)
        {
            return {false, {}};
        }

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * G;

        if (public_ephemeral != public_keys[real_output_index])
        {
            return {false, {}};
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

        // compute HP for the real output once — reused for key image and signing
        const auto HP_real = hash_t::sha3(public_keys[real_output_index]).point();

        // generate key image: I = [Hp(P) * x] mod l
        const auto key_image = secret_ephemeral * HP_real;

    try_again:
        // Derive nonce by hashing message, key image, public keys, and fresh randomness
        scalar_transcript_t alpha_transcript(message_digest, key_image, scalar_t::random());

        alpha_transcript.update(public_keys);

        const auto alpha_scalar = alpha_transcript.challenge();

        // A zero or unreduced nonce would leak the secret key in the response scalar computation
        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        std::vector<signature_t> signature(ring_size);

        scalar_t sum;

        scalar_transcript_t transcript(BORROMEAN_DOMAIN_0, message_digest);

        // Build (L, R) pairs: real member uses the nonce; decoys use random scalars
        for (size_t i = 0; i < ring_size; i++)
        {
            point_t L, R;

            if (i == real_output_index)
            {
                // L = alpha * G, R = alpha * Hp(P) — commitment using the nonce
                L = alpha_scalar * G;

                R = alpha_scalar * HP_real;
            }
            else
            {
                // HP = [Hp(P)] mod l
                const auto HP = hash_t::sha3(public_keys[i]).point();

                signature[i].LR.L = scalar_t::random();

                signature[i].LR.R = scalar_t::random();

                // L = [(s[i].L * P) + (s[i].R * G)] mod l
                L = signature[i].LR.L.dbl_mult(public_keys[i], signature[i].LR.R, Crypto::G);

                // R = [(s[i].R * I) + (s[i].L * HP)] mod l
                R = signature[i].LR.R.dbl_mult(HP, signature[i].LR.L, key_image);

                // sum += s[i].L
                sum += signature[i].LR.L;
            }

            transcript.update(L, R);
        }

        const auto challenge = transcript.challenge();

        if (!challenge.valid())
        {
            goto try_again;
        }

        // Close the ring: real member's challenge absorbs the difference so the sum matches
        signature[real_output_index].LR.L = challenge - sum;

        // Response scalar: r = alpha - c_real * x (Schnorr-like closing for the real member)
        signature[real_output_index].LR.R = alpha_scalar - (signature[real_output_index].LR.L * secret_ephemeral);

        return {true, borromean_signature_t(signature)};
    }
} // namespace Crypto::RingSignature::Borromean
