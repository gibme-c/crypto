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
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

#include <cstring>

#include <crypto_constants.h>
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/gray_code_generator_t.h>
#include <helpers/scalar_transcript_t.h>
#include <signatures/ring_signature_triptych.h>

typedef std::vector<std::vector<crypto_scalar_t>> triptych_crypto_scalar_vector_t;

static inline crypto_point_t commitment_tensor(const triptych_crypto_scalar_vector_t &v, const crypto_scalar_t &r)
{
    // count total terms: all v[i][j] pairs + the final r*H term
    size_t count = 0;

    for (size_t i = 0; i < v.size(); ++i)
    {
        count += v[i].size();
    }

    count++; // for r * H

    // build contiguous scalar and point arrays for MSM
    std::vector<unsigned char> scalars(count * 32);
    std::vector<ge_p3> points(count);

    size_t idx = 0;

    for (size_t i = 0; i < v.size(); ++i)
    {
        for (size_t j = 0; j < v[i].size(); ++j)
        {
            std::memcpy(&scalars[idx * 32], v[i][j].data(), 32);
            points[idx] = Crypto::commitment_tensor_point(TRIPTYCH_DOMAIN_1, i, j).p3();
            idx++;
        }
    }

    // final term: r * H
    std::memcpy(&scalars[idx * 32], r.data(), 32);
    points[idx] = Crypto::H.p3();

    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
    ge_multiscalar_mul_vartime(&result, scalars.data(), points.data(), count);

    return crypto_point_t(result);
}

static inline triptych_crypto_scalar_vector_t init_triptych_scalar_vector(
    size_t d1,
    size_t d2,
    bool random = false,
    const crypto_scalar_t &initial_value = Crypto::ZERO)
{
    triptych_crypto_scalar_vector_t result(d1);

    for (auto &level1 : result)
    {
        if (random)
        {
            level1 = crypto_scalar_t::random(d2);
        }
        else
        {
            level1 = std::vector<crypto_scalar_t>(d2, initial_value);
        }
    }

    return result;
}

namespace Crypto::RingSignature::Triptych
{
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_triptych_signature_t &signature,
        const std::vector<crypto_pedersen_commitment_t> &commitments)
    {
        const size_t n = 2;

        // check to verify that there are no duplicate keys in the set
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return false;
            }
        }

        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found || m < 2)
        {
            return false;
        }

        if (public_keys.size() != commitments.size())
        {
            return false;
        }

        if (!key_image.check_subgroup())
        {
            return false;
        }

        if (!signature.check_construction(m, n))
        {
            return false;
        }

        auto tr = scalar_transcript_t(TRIPTYCH_DOMAIN_0, message_digest);

        tr.update(public_keys);

        tr.update(commitments);

        tr.update(signature.pseudo_commitment);

        tr.update(key_image);

        tr.update(signature.commitment_image);

        tr.update(signature.A);

        tr.update(signature.B);

        tr.update(signature.C);

        tr.update(signature.D);

        const auto mu = tr.challenge();

        if (!mu.valid())
        {
            return false;
        }

        tr.update(signature.X);

        tr.update(signature.Y);

        const auto x = tr.challenge();

        if (!x.valid())
        {
            return false;
        }

        auto f = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            f[j][0] = x;

            for (size_t i = 1; i < n; ++i)
            {
                f[j][i] = signature.f[j][i - 1];

                f[j][0] -= f[j][i];
            }
        }

        // A/B Check
        for (size_t j = 0; j < m; ++j)
        {
            f[j][0] = x;

            for (size_t i = 1; i < n; ++i)
            {
                f[j][0] -= f[j][i];
            }
        }

        if (commitment_tensor(f, signature.zA) != (x * signature.B) + signature.A)
        {
            return false;
        }

        auto fx = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                fx[j][i] = f[j][i] * (x - f[j][i]);
            }
        }

        if (commitment_tensor(fx, signature.zC) != (x * signature.C) + signature.D)
        {
            return false;
        }

        const auto N = public_keys.size();

        // total terms: N (gray code) + m (X[j]/Y[j]) + 1 (z*G or z*I)
        const auto total_terms = N + m + 1;

        // RY: the second point in the gray code loop is constant:
        // U + mu * commitment_image, so RY's gray code portion is
        // (sum of t_k) * constant_RY_point, collapsible to 1 term
        const auto RY_gray_point = Crypto::U + (mu * signature.commitment_image);

        // Build RX MSM: N gray code terms + m X[j] terms + z*G (base variant)
        std::vector<unsigned char> rx_scalars(total_terms * 32);
        std::vector<ge_p3> rx_points(total_terms);

        // Build RY MSM: 1 collapsed gray code term + m Y[j] terms + z*I
        const auto ry_total = m + 2;
        std::vector<unsigned char> ry_scalars(ry_total * 32);
        std::vector<ge_p3> ry_points(ry_total);

        auto t = Crypto::ONE;

        for (size_t j = 0; j < m; ++j)
        {
            t *= f[j][0];
        }

        // accumulate the sum of all t values for the collapsed RY gray code term
        auto t_sum = t;

        gray_code_generator_t gray_codes(n, m);

        // gray code terms for RX (positive)
        std::memcpy(&rx_scalars[0], t.data(), 32);
        rx_points[0] = (public_keys[0] + (mu * (Crypto::EIGHT * (commitments[0] - signature.pseudo_commitment)))).p3();

        for (size_t k = 1; k < N; ++k)
        {
            const auto &gray_update = gray_codes[k];

            t *= f[gray_update[0]][gray_update[1]].invert() * f[gray_update[0]][gray_update[2]];

            t_sum += t;

            std::memcpy(&rx_scalars[k * 32], t.data(), 32);
            rx_points[k] =
                (public_keys[k] + (mu * (Crypto::EIGHT * (commitments[k] - signature.pseudo_commitment)))).p3();
        }

        // X[j] and Y[j] terms (negated: subtraction)
        for (size_t j = 0; j < m; ++j)
        {
            const auto neg_xpow = x.pow(j).negate();

            std::memcpy(&rx_scalars[(N + j) * 32], neg_xpow.data(), 32);
            rx_points[N + j] = signature.X[j].p3();

            std::memcpy(&ry_scalars[(1 + j) * 32], neg_xpow.data(), 32);
            ry_points[1 + j] = signature.Y[j].p3();
        }

        // RX: z*G term via base variant (negated)
        const auto neg_z = signature.z.negate();

        // RY: collapsed gray code term (t_sum * RY_gray_point)
        std::memcpy(&ry_scalars[0], t_sum.data(), 32);
        ry_points[0] = RY_gray_point.p3();

        // RY: z * key_image term (negated)
        std::memcpy(&ry_scalars[(m + 1) * 32], neg_z.data(), 32);
        ry_points[m + 1] = key_image.p3();

        // compute RX = base_scalar*G + sum(scalars[i]*points[i])
        ge_p3 rx_result; // NOLINT: immediately populated by ge_multiscalar_mul
        ge_multiscalar_mul_base_vartime(
            &rx_result, rx_scalars.data(), rx_points.data(), N + m, neg_z.data());

        // compute RY
        ge_p3 ry_result; // NOLINT: immediately populated by ge_multiscalar_mul
        ge_multiscalar_mul_vartime(&ry_result, ry_scalars.data(), ry_points.data(), ry_total);

        return crypto_point_t(rx_result).empty() && crypto_point_t(ry_result).empty();
    }

    std::tuple<bool, crypto_triptych_signature_t> complete_ring_signature(
        const crypto_scalar_t &signing_scalar,
        const crypto_triptych_signature_t &signature,
        const crypto_scalar_t &xpow)
    {
        if (!signing_scalar.valid() || !xpow.valid())
        {
            return {false, {}};
        }


        auto finalized_signature = signature;

        finalized_signature.z += (signing_scalar * xpow);

        return {true, finalized_signature};
    }

    std::tuple<bool, crypto_triptych_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
    {
        if (!secret_ephemeral.valid() || !input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
        {
            return {false, {}};
        }

        const auto ring_size = public_keys.size();

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * Crypto::G;

        const auto public_commitment = (input_blinding_factor - pseudo_blinding_factor) * Crypto::G;

        // constant-time scan: check all elements, count matches
        size_t real_output_index = ring_size; // sentinel
        size_t match_count = 0;

        for (size_t i = 0; i < ring_size; i++)
        {
            const auto derived_commitment = Crypto::EIGHT * (input_commitments[i] - pseudo_commitment);

            if (public_ephemeral == public_keys[i] && public_commitment == derived_commitment)
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
            message_digest, secret_ephemeral, public_keys, real_output_index,
            input_blinding_factor, input_commitments, pseudo_blinding_factor, pseudo_commitment);
    }

    std::tuple<bool, crypto_triptych_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
    {
        // check to verify that there are no duplicate keys in the set
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return {false, {}};
            }
        }

        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found || m < 2)
        {
            return {false, {}};
        }

        if (public_keys.size() != input_commitments.size())
        {
            return {false, {}};
        }

        const auto ring_size = public_keys.size();

        if (!secret_ephemeral.valid() || !input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
        {
            return {false, {}};
        }

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

        const auto public_commitment = (input_blinding_factor - pseudo_blinding_factor) * Crypto::G;

        const auto derived_commitment =
            Crypto::EIGHT * (input_commitments[real_output_index] - pseudo_commitment);

        if (public_commitment != derived_commitment)
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

        const auto key_image = Crypto::generate_key_image_v2(secret_ephemeral);

        const auto [gen_success, signature, x_pow] = prepare_ring_signature(
            message_digest,
            key_image,
            public_keys,
            real_output_index,
            input_blinding_factor,
            input_commitments,
            pseudo_blinding_factor,
            pseudo_commitment);

        if (!gen_success)
        {
            return {false, {}};
        }

        return complete_ring_signature(secret_ephemeral, signature, x_pow);
    }

    std::tuple<bool, crypto_triptych_signature_t, crypto_scalar_t> prepare_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index,
        const crypto_blinding_factor_t &input_blinding_factor,
        const std::vector<crypto_pedersen_commitment_t> &input_commitments,
        const crypto_blinding_factor_t &pseudo_blinding_factor,
        const crypto_pedersen_commitment_t &pseudo_commitment)
    {
        const size_t n = 2;

        // check to verify that there are no duplicate keys in the set
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return {false, {}, {}};
            }
        }

        // checks to verify that it is a proper power of two
        const auto [m_found, m] = Crypto::calculate_base2_exponent(public_keys.size());

        if (!m_found || m < 2)
        {
            return {false, {}, {}};
        }

        if (public_keys.size() != input_commitments.size())
        {
            return {false, {}, {}};
        }

        if (!key_image.check_subgroup())
        {
            return {false, {}, {}};
        }

        if (!input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
        {
            return {false, {}, {}};
        }

        // See below for more detail
        const auto blinding_factor = input_blinding_factor - pseudo_blinding_factor;

        /**
         * TLDR: If we know the difference between the input blinding scalar and the
         * pseudo output blinding scalar then we can use that difference as the secret
         * key for the difference between the input commitment and the pseudo commitment
         * thus providing no amount component differences in the commitments between the
         * two and hence we are committing (in a non-revealing way) that the pseudo output
         * commitment is equivalent to ONE of the input commitments in the set
         */
        const auto commitment = Crypto::EIGHT * (input_commitments[real_output_index] - pseudo_commitment);

        const auto public_commitment = blinding_factor * Crypto::G;

        /**
         * Quick sanity check to make sure that the computed blinding factor delta has a
         * resulting public point that is the same as the commitment that we can sign for above
         */
        if (commitment != public_commitment)
        {
            return {false, {}, {}};
        }

        auto N = public_keys.size();

        const crypto_key_image_t commitment_image = (input_blinding_factor - pseudo_blinding_factor) * key_image;

    try_again:
        const auto rA = crypto_scalar_t::random(), rB = crypto_scalar_t::random(), rC = crypto_scalar_t::random(),
                   rD = crypto_scalar_t::random();

        if (!rA.valid() || !rB.valid() || !rC.valid() || !rD.valid())
        {
            goto try_again;
        }

        auto a = init_triptych_scalar_vector(m, n, true);

        for (size_t j = 0; j < m; ++j)
        {
            a[j][0] = Crypto::ZERO;

            for (size_t i = 1; i < n; ++i)
            {
                a[j][0] -= a[j][i];
            }
        }

        const auto A = commitment_tensor(a, rA);

        const auto gray = gray_code_generator_t(n, m, real_output_index);

        const auto decomp_l = gray.v_value();

        auto sigma = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                sigma[j][i] = Crypto::kronecker_delta(decomp_l[j], i);
            }
        }

        const auto B = commitment_tensor(sigma, rB);

        auto a_sigma = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                a_sigma[j][i] = a[j][i] * (Crypto::ONE - Crypto::TWO * sigma[j][i]);
            }
        }

        const auto C = commitment_tensor(a_sigma, rC);

        auto a_sq = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                a_sq[j][i] = a[j][i].squared().negate();
            }
        }

        const auto D = commitment_tensor(a_sq, rD);

        auto p = init_triptych_scalar_vector(N, 0);

        auto decomp_k = std::vector<int>(m, 0);

        gray_code_generator_t gray_codes(n, m);

        for (size_t k = 0; k < gray_codes.size(); ++k)
        {
            const auto &gray_update = gray_codes[k];

            decomp_k[gray_update[0]] = gray_update[2];

            p[k] = {a[0][decomp_k[0]], Crypto::kronecker_delta(decomp_l[0], decomp_k[0])};

            for (size_t j = 1; j < m; ++j)
            {
                p[k] = Crypto::convolve(
                    crypto_scalar_vector_t(p[k]),
                    {a[j][decomp_k[j]], Crypto::kronecker_delta(decomp_l[j], decomp_k[j])});
            }
        }

        std::vector<crypto_point_t> X(m, Crypto::Z), Y(m, Crypto::Z);

        auto tr = scalar_transcript_t(TRIPTYCH_DOMAIN_0, message_digest);

        tr.update(public_keys);

        tr.update(input_commitments);

        tr.update(pseudo_commitment);

        tr.update(key_image);

        tr.update(commitment_image);

        tr.update(A);

        tr.update(B);

        tr.update(C);

        tr.update(D);

        const auto mu = tr.challenge();

        if (!mu.valid())
        {
            goto try_again;
        }

        const auto rho = crypto_scalar_t::random(m);

        for (const auto &r : rho)
        {
            if (!r.valid())
            {
                goto try_again;
            }
        }

        // precompute combined points for each ring member
        std::vector<ge_p3> combined_points(N);

        for (size_t i = 0; i < N; ++i)
        {
            combined_points[i] =
                (public_keys[i] + (mu * (Crypto::EIGHT * (input_commitments[i] - pseudo_commitment)))).p3();
        }

        const auto key_image_p3 = key_image.p3();
        const auto U_p3 = Crypto::U.p3();

        for (size_t j = 0; j < m; ++j)
        {
            // X[j] = sum(p[i][j] * combined_point[i]) + rho[j] * G
            {
                std::vector<unsigned char> scalars(N * 32);
                auto p_sum = Crypto::ZERO;

                for (size_t i = 0; i < N; ++i)
                {
                    std::memcpy(&scalars[i * 32], p[i][j].data(), 32);
                    p_sum += p[i][j];
                }

                ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                ge_multiscalar_mul_base_vartime(&result, scalars.data(), combined_points.data(), N, rho[j].data());

                X[j] = crypto_point_t(result);
            }

            // Y[j] = (sum of p[i][j]) * U + rho[j] * key_image
            // All N terms share the same point U, so collapse to a single scalar mult
            {
                auto p_sum = Crypto::ZERO;

                for (size_t i = 0; i < N; ++i)
                {
                    p_sum += p[i][j];
                }

                unsigned char scalars[2 * 32];
                ge_p3 points[2];

                std::memcpy(&scalars[0], p_sum.data(), 32);
                points[0] = U_p3;
                std::memcpy(&scalars[32], rho[j].data(), 32);
                points[1] = key_image_p3;

                ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                ge_multiscalar_mul_vartime(&result, scalars, points, 2);

                Y[j] = crypto_point_t(result);
            }
        }

        tr.update(X);

        tr.update(Y);

        const auto x = tr.challenge();

        if (!x.valid())
        {
            goto try_again;
        }

        auto f = init_triptych_scalar_vector(m, n - 1);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 1; i < n; ++i)
            {
                f[j][i - 1] = (sigma[j][i] * x) + a[j][i];
            }
        }

        const auto zA = rB * x + rA;

        const auto zC = rC * x + rD;

        const auto xpow = x.pow(m);

        auto z = (mu * (input_blinding_factor - pseudo_blinding_factor)) * xpow;

        for (size_t j = 0; j < m; ++j)
        {
            z -= rho[j] * x.pow(j);
        }

        const auto signature =
            crypto_triptych_signature_t(commitment_image, pseudo_commitment, A, B, C, D, X, Y, f, zA, zC, z);

        return {true, signature, xpow};
    }
} // namespace Crypto::RingSignature::Triptych
