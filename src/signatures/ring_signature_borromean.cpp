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

#include <crypto_constants.h>
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/scalar_transcript_t.h>
#include <signatures/ring_signature_borromean.h>

namespace Crypto::RingSignature::Borromean
{
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_borromean_signature_t &borromean_signature)
    {
        // check to verify that there are no duplicate keys in the set
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

        crypto_scalar_t sum;

        scalar_transcript_t transcript(BORROMEAN_DOMAIN_0, message_digest);

        for (size_t i = 0; i < ring_size; i++)
        {
            // HP = [Hp(P)] mod l
            const auto HP = crypto_hash_t::sha3(public_keys[i]).point();

            // L = [(s[i].L * P) + (s[i].R * G)] mod l
            const auto L = signature[i].LR.L.dbl_mult(public_keys[i], signature[i].LR.R, Crypto::G);

            // R = [(s[i].R * HP) + (s[i].L * I)] mod l
            const auto R = signature[i].LR.R.dbl_mult(HP, signature[i].LR.L, key_image);

            // sum += L
            sum += signature[i].LR.L;

            transcript.update(L, R);
        }

        const auto challenge = transcript.challenge();

        if (!challenge.valid())
        {
            return false;
        }

        // ([H(prefix || L || R) - sum] mod l) == 0
        return !(challenge - sum).is_nonzero();
    }

    std::tuple<bool, crypto_borromean_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys)
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

        // find our real output in the list
        size_t real_output_index = -1;

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * G;

        for (size_t i = 0; i < ring_size; i++)
        {
            if (public_ephemeral == public_keys[i])
            {
                real_output_index = i;

                break;
            }
        }

        // if we could not find the public ephemeral in the list, fail
        if (real_output_index == -1)
        {
            return {false, {}};
        }

        // compute HP for the real output once — reused for key image and signing
        const auto HP_real = crypto_hash_t::sha3(public_keys[real_output_index]).point();

        // generate key image: I = [Hp(P) * x] mod l
        const auto key_image = secret_ephemeral * HP_real;

    try_again:
        // help to provide stronger RNG for the alpha scalar
        scalar_transcript_t alpha_transcript(message_digest, key_image, crypto_scalar_t::random());

        alpha_transcript.update(public_keys);

        const auto alpha_scalar = alpha_transcript.challenge();

        /**
         * An alpha_scalar of ZERO results in a leakage of the real signing key in the resulting
         * signature construction mechanisms
         */
        if (alpha_scalar == ZERO)
        {
            return {false, {}};
        }

        std::vector<crypto_signature_t> signature(ring_size);

        crypto_scalar_t sum;

        scalar_transcript_t transcript(BORROMEAN_DOMAIN_0, message_digest);

        for (size_t i = 0; i < ring_size; i++)
        {
            crypto_point_t L, R;

            if (i == real_output_index)
            {
                // L = (alpha_scalar * G) mod l
                L = alpha_scalar * G;

                // R = (alpha_scalar * HP) mod l — reuse precomputed HP_real
                R = alpha_scalar * HP_real;
            }
            else
            {
                // HP = [Hp(P)] mod l
                const auto HP = crypto_hash_t::sha3(public_keys[i]).point();

                signature[i].LR.L = crypto_scalar_t::random();

                signature[i].LR.R = crypto_scalar_t::random();

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

        // sL = ([H(prefix || L's || R's)] - sum) mod l
        signature[real_output_index].LR.L = challenge - sum;

        // s[i].R = [alpha_scalar - (p * sL)] mod l
        signature[real_output_index].LR.R = alpha_scalar - (signature[real_output_index].LR.L * secret_ephemeral);

        return {true, crypto_borromean_signature_t(signature)};
    }
} // namespace Crypto::RingSignature::Borromean
