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
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

/**
 * @file triptych.cpp
 * @brief Triptych logarithmic-size ring signatures using base-n matrix decomposition of the
 *        signer index and Gray code optimization for product evaluation.
 */

#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <cstring>
#include <helpers/constant_time.h>
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/gray_code_generator_t.h>
#include <helpers/math_helpers.h>
#include <helpers/scalar_transcript_t.h>
#include <serialization.h>
#include <triptych/triptych.h>
#include <stdexcept>

static inline point_t commitment_tensor_point(const point_t &point, size_t i, size_t j, size_t k = 0)
{
    auto writer = Serialization::serializer_t();

    writer.pod(point);

    writer.uint64(i);

    writer.uint64(j);

    writer.uint64(k);

    return hash_t::sha3(writer).point();
}

static inline std::vector<scalar_t> convolve(const scalar_vector_t &x, const std::vector<scalar_t> &y)
{
    if (y.size() != 2)
    {
        throw std::runtime_error("requires a degree-one polynomial");
    }

    std::vector<scalar_t> result(x.size() + 1, Crypto::ZERO);

    for (size_t i = 0; i < x.size(); ++i)
    {
        for (size_t j = 0; j < y.size(); ++j)
        {
            result[i + j] += x[i] * y[j];
        }
    }

    return result;
}

static inline scalar_t kronecker_delta(const scalar_t &a, const scalar_t &b)
{
    if (a == b)
    {
        return Crypto::ONE;
    }

    return Crypto::ZERO;
}

static inline scalar_t kronecker_delta(size_t a, size_t b)
{
    return kronecker_delta(scalar_t(a), scalar_t(b));
}

typedef std::vector<std::vector<scalar_t>> triptych_crypto_scalar_vector_t;

// Compute a Pedersen-like vector commitment: sum(v[i][j] * G_{i,j}) + r*H via MSM
static inline point_t commitment_tensor(const triptych_crypto_scalar_vector_t &v, const scalar_t &r)
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
            points[idx] = commitment_tensor_point(TRIPTYCH_DOMAIN_1, i, j).p3();
            idx++;
        }
    }

    // final term: r * H
    std::memcpy(&scalars[idx * 32], r.data(), 32);
    points[idx] = Crypto::H.p3();

    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
    ge_multiscalar_mul_vartime(&result, scalars.data(), points.data(), count);

    return point_t(result);
}

// Allocate an m x n scalar matrix, optionally filled with random values or a constant
static inline triptych_crypto_scalar_vector_t
    init_triptych_scalar_vector(size_t d1, size_t d2, bool random = false, const scalar_t &initial_value = Crypto::ZERO)
{
    triptych_crypto_scalar_vector_t result(d1);

    for (auto &level1 : result)
    {
        if (random)
        {
            level1 = scalar_t::random(d2);
        }
        else
        {
            level1 = std::vector<scalar_t>(d2, initial_value);
        }
    }

    return result;
}

namespace Crypto::RingSignature::Triptych
{
    // ---- Verify: reconstruct X/Y proof points and check they sum to zero ----

    bool check_ring_signature(
        const hash_t &message_digest,
        const key_image_t &key_image,
        const std::vector<public_key_t> &public_keys,
        const triptych_signature_t &signature,
        const std::vector<pedersen_commitment_t> &commitments)
    {
        const size_t n = 2; // base of the decomposition (binary)

        // Reject rings with duplicate public keys
        {
            const auto keys = dedupe_and_sort_keys(public_keys);

            if (keys.size() != public_keys.size())
            {
                return false;
            }
        }

        // Ring size must be a power of 2 (N = n^m); m is the number of decomposition digits
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

        // ---- Derive challenges mu and x from the Fiat-Shamir transcript ----
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

        // ---- Reconstruct the f matrix from signature data ----
        // f[j][0] = x - sum(f[j][1..n-1]), ensuring each row sums to x
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

        // ---- Commitment tensor checks: verify A/B and C/D consistency ----
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

        // ---- Verification equations for X and Y via MSM ----
        // RX checks the public-key/commitment component; RY checks the key-image component.
        // Gray code trick: evaluate product(f[j][k_j]) for all k in [0,N) incrementally.
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
        ge_multiscalar_mul_base_vartime(&rx_result, rx_scalars.data(), rx_points.data(), N + m, neg_z.data());

        // compute RY
        ge_p3 ry_result; // NOLINT: immediately populated by ge_multiscalar_mul
        ge_multiscalar_mul_vartime(&ry_result, ry_scalars.data(), ry_points.data(), ry_total);

        // Both equations must evaluate to the identity point (zero)
        return point_t(rx_result).empty() && point_t(ry_result).empty();
    }

    // ---- Sign (auto-detect signer index): find our key in the ring, then delegate ----

    std::tuple<bool, triptych_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys,
        const blinding_factor_t &input_blinding_factor,
        const std::vector<pedersen_commitment_t> &input_commitments,
        const blinding_factor_t &pseudo_blinding_factor,
        const pedersen_commitment_t &pseudo_commitment)
    {
        if (!secret_ephemeral.valid() || !input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
        {
            return {false, {}};
        }

        const auto ring_size = public_keys.size();

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * Crypto::G;

        const auto public_commitment = (input_blinding_factor - pseudo_blinding_factor) * Crypto::G;

        // constant-time scan: check all elements, count matches.
        // Uses conditional-move to update the index without branching on match.
        size_t real_output_index = ring_size; // sentinel
        size_t match_count = 0;

        for (size_t i = 0; i < ring_size; i++)
        {
            const auto derived_commitment = Crypto::EIGHT * (input_commitments[i] - pseudo_commitment);

            const bool match = (public_ephemeral == public_keys[i] && public_commitment == derived_commitment);

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
            input_commitments,
            pseudo_blinding_factor,
            pseudo_commitment);
    }

    // ---- Sign (explicit signer index): full proof construction ----

    std::tuple<bool, triptych_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys,
        size_t real_output_index,
        const blinding_factor_t &input_blinding_factor,
        const std::vector<pedersen_commitment_t> &input_commitments,
        const blinding_factor_t &pseudo_blinding_factor,
        const pedersen_commitment_t &pseudo_commitment)
    {
        const size_t n = 2; // base of the decomposition (binary)

        // Reject rings with duplicate public keys
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

        const auto N = public_keys.size();

        if (!secret_ephemeral.valid() || !input_blinding_factor.valid() || !pseudo_blinding_factor.valid())
        {
            return {false, {}};
        }

        if (real_output_index >= N)
        {
            return {false, {}};
        }

        // P = (p * G) mod l
        const auto public_ephemeral = secret_ephemeral * Crypto::G;

        if (public_ephemeral != public_keys[real_output_index])
        {
            return {false, {}};
        }

        // The blinding factor difference lets us prove the pseudo commitment hides
        // the same amount as the real input commitment, without revealing either.
        const auto blinding_factor = input_blinding_factor - pseudo_blinding_factor;

        const auto derived_commitment = Crypto::EIGHT * (input_commitments[real_output_index] - pseudo_commitment);

        const auto public_commitment = blinding_factor * Crypto::G;

        // Sanity check: blinding_factor * G must equal the commitment difference
        if (public_commitment != derived_commitment)
        {
            return {false, {}};
        }

        // validate uniqueness (defense-in-depth — dedupe_and_sort_keys already rejects duplicates)
        size_t match_count = 0;

        for (size_t i = 0; i < N; i++)
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

        if (!key_image.check_subgroup())
        {
            return {false, {}};
        }

        const key_image_t commitment_image = blinding_factor * key_image;

    try_again:
        // ---- Generate random blinding scalars for the four tensor commitments (A, B, C, D) ----
        const auto rA = scalar_t::random(), rB = scalar_t::random(), rC = scalar_t::random(), rD = scalar_t::random();

        if (!rA.valid() || !rB.valid() || !rC.valid() || !rD.valid())
        {
            goto try_again;
        }

        // Random masking matrix 'a' with each row summing to zero
        auto a = init_triptych_scalar_vector(m, n, true);

        for (size_t j = 0; j < m; ++j)
        {
            a[j][0] = Crypto::ZERO;

            for (size_t i = 1; i < n; ++i)
            {
                a[j][0] -= a[j][i];
            }
        }

        // A = Com(a, rA) — commitment to the masking matrix
        const auto A = commitment_tensor(a, rA);

        // Decompose the real signer index into base-n digits
        const auto gray = gray_code_generator_t(n, m, real_output_index);

        const auto decomp_l = gray.v_value();

        // sigma[j][i] = kronecker_delta(decomp_l[j], i) — one-hot encoding of the signer index
        auto sigma = init_triptych_scalar_vector(m, n);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 0; i < n; ++i)
            {
                sigma[j][i] = kronecker_delta(decomp_l[j], i);
            }
        }

        // B = Com(sigma, rB) — commitment to the one-hot signer encoding
        const auto B = commitment_tensor(sigma, rB);

        // C/D prove that sigma contains only 0s and 1s (quadratic constraint)
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

        // ---- Compute polynomial coefficients p[k][j] via convolution ----
        // p[k] is the convolution of per-digit (a, sigma) pairs, evaluated at each ring index k.
        auto p = init_triptych_scalar_vector(N, 0);

        auto decomp_k = std::vector<int>(m, 0);

        gray_code_generator_t gray_codes(n, m);

        for (size_t k = 0; k < gray_codes.size(); ++k)
        {
            const auto &gray_update = gray_codes[k];

            decomp_k[gray_update[0]] = gray_update[2];

            p[k] = {a[0][decomp_k[0]], kronecker_delta(decomp_l[0], decomp_k[0])};

            for (size_t j = 1; j < m; ++j)
            {
                p[k] = convolve(scalar_vector_t(p[k]), {a[j][decomp_k[j]], kronecker_delta(decomp_l[j], decomp_k[j])});
            }
        }

        // ---- Build proof points X[j] and Y[j] ----
        std::vector<point_t> X(m, Crypto::Z), Y(m, Crypto::Z);

        // Derive first challenge mu from the transcript (binds A, B, C, D)
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

        const auto rho = scalar_t::random(m);

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

                for (size_t i = 0; i < N; ++i)
                {
                    std::memcpy(&scalars[i * 32], p[i][j].data(), 32);
                }

                ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                ge_multiscalar_mul_base_vartime(&result, scalars.data(), combined_points.data(), N, rho[j].data());

                X[j] = point_t(result);
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

                Y[j] = point_t(result);
            }
        }

        // ---- Derive second challenge x from X and Y, then compute response scalars ----
        tr.update(X);

        tr.update(Y);

        const auto x = tr.challenge();

        if (!x.valid())
        {
            goto try_again;
        }

        // f[j][i] = sigma[j][i]*x + a[j][i] — only i >= 1 stored (i=0 is implicit)
        auto f = init_triptych_scalar_vector(m, n - 1);

        for (size_t j = 0; j < m; ++j)
        {
            for (size_t i = 1; i < n; ++i)
            {
                f[j][i - 1] = (sigma[j][i] * x) + a[j][i];
            }
        }

        // Blinding response scalars for the tensor commitments
        const auto zA = rB * x + rA;

        const auto zC = rC * x + rD;

        // z aggregates the commitment blinding, per-round rho masking, and secret key
        const auto xpow = x.pow(m);

        auto z = (mu * blinding_factor + secret_ephemeral) * xpow;

        for (size_t j = 0; j < m; ++j)
        {
            z -= rho[j] * x.pow(j);
        }

        return {true, triptych_signature_t(commitment_image, pseudo_commitment, A, B, C, D, X, Y, f, zA, zC, z)};
    }

} // namespace Crypto::RingSignature::Triptych
