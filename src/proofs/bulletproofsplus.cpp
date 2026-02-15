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
// https://github.com/SarangNoether/skunkworks/tree/pybullet-plus

#include <crypto_constants.h>
#include <ge_double_scalarmult_negate_vartime_batch_ss_p3.h>
#include <ge_multiscalar_mul_vartime.h>
#include <helpers/scalar_transcript_t.h>
#include <mutex>
#include <proofs/bulletproofsplus.h>
#include <proofs/ringct.h>
#undef max

static const auto powers_of_two = Crypto::TWO.pow_expand(64);

static std::mutex bulletproofsplus_mutex;

/**
 * Generates the general bulletproof exponents up through the given count
 * to aid in the speed of proving and verifying, the exponents are cached
 * and if more are requested, then they are generated on demand; otherwise,
 * if less are requested, we supply a slice of the cached entries thus
 * avoiding doing a whole bunch of hashing each generation and verification
 * @param count
 * @return
 */
static std::tuple<crypto_point_vector_t, crypto_point_vector_t> generate_exponents(size_t count)
{
    std::scoped_lock lock(bulletproofsplus_mutex);

    static crypto_point_vector_t L_cached, R_cached;

    if (count == L_cached.size() && count == R_cached.size())
    {
        return {L_cached, R_cached};
    }

    if (count < L_cached.size())
    {
        return {L_cached.slice(0, count), R_cached.slice(0, count)};
    }

    auto writer = Serialization::serializer_t();

    for (size_t i = L_cached.size(); i < count; ++i)
    {
        writer.reset();

        writer.uint64(i);

        writer.pod(BULLETPROOFS_PLUS_DOMAIN_1);

        L_cached.append(crypto_hash_t::sha3(writer).point());

        writer.pod(BULLETPROOFS_PLUS_DOMAIN_2);

        R_cached.append(crypto_hash_t::sha3(writer).point());
    }

    return {L_cached, R_cached};
}

namespace Crypto::RangeProofs::BulletproofsPlus
{
    /**
     * Helps to calculate an inner product round
     */
    struct InnerProductRound
    {
        InnerProductRound(
            crypto_point_vector_t Gi,
            crypto_point_vector_t Hi,
            crypto_scalar_vector_t a,
            crypto_scalar_vector_t b,
            const crypto_scalar_t &alpha,
            const crypto_scalar_t &y,
            scalar_transcript_t tr):
            Gi(std::move(Gi)),
            Hi(std::move(Hi)),
            a(std::move(a)),
            b(std::move(b)),
            alpha(alpha),
            y(y),
            tr(std::move(tr))
        {
        }

        std::tuple<
            crypto_point_t,
            crypto_point_t,
            crypto_scalar_t,
            crypto_scalar_t,
            crypto_scalar_t,
            std::vector<crypto_point_t>,
            std::vector<crypto_point_t>>
            compute()
        {
            if (done)
            {
                return {A, B, r1, s1, d1, L.container, R.container};
            }

            auto n = Gi.size();

            // Precompute y_inv once and y-power tables for all rounds
            const auto y_inv_local = y.invert();

            // Build ypow/yinvpow tables: index k holds y^(2^k) and y_inv^(2^k)
            // Round with half-size n needs y^n where n = size/2 at that point
            size_t logN = 0;

            for (size_t nn = n; nn > 1; nn /= 2)
            {
                logN++;
            }

            std::vector<crypto_scalar_t> ypow_table(logN), yinvpow_table(logN);

            {
                auto yp = y, yip = y_inv_local;

                for (size_t k = 0; k < logN; ++k)
                {
                    ypow_table[k] = yp;
                    yinvpow_table[k] = yip;

                    if (k + 1 < logN)
                    {
                        yp = yp.squared();
                        yip = yip.squared();
                    }
                }
            }

            size_t round_idx = 0;

            // Extract raw ge_p3 arrays (avoids repeated .p3() calls and crypto_point_t overhead)
            std::vector<ge_p3> Gi_p3(n), Hi_p3(n);
            for (size_t i = 0; i < n; ++i)
            {
                Gi_p3[i] = Gi.container[i].p3();
            }
            for (size_t i = 0; i < n; ++i)
            {
                Hi_p3[i] = Hi.container[i].p3();
            }

            // Pre-allocate MSM buffers and cache constant points
            const size_t max_total = n + 2; // 2*(n/2)+2
            std::vector<unsigned char> msm_scalars(max_total * 32);
            std::vector<ge_p3> msm_points(max_total);
            const auto H_p3 = Crypto::H.p3();
            const auto G_p3 = Crypto::G.p3();
            const auto inv8 = Crypto::INV_EIGHT;

            while (n > 1)
            {
                n /= 2;

                const auto dL = crypto_scalar_t::random(), dR = crypto_scalar_t::random();

                if (!dL.valid() || !dR.valid())
                {
                    throw std::runtime_error("d values cannot be zero");
                }

                const auto &ypow = ypow_table[logN - 1 - round_idx];
                const auto &yinvpow = yinvpow_table[logN - 1 - round_idx];

                // Weighted inner products computed directly (no slices)
                auto cL = Crypto::ZERO;
                {
                    auto y_power = y;
                    for (size_t i = 0; i < n; ++i)
                    {
                        cL += a.container[i] * y_power * b.container[n + i];
                        y_power *= y;
                    }
                }

                auto cR = Crypto::ZERO;
                {
                    auto y_power = y;
                    for (size_t i = 0; i < n; ++i)
                    {
                        cR += (a.container[n + i] * ypow) * y_power * b.container[i];
                        y_power *= y;
                    }
                }

                const size_t total = 2 * n + 1;

                // L = INV_EIGHT * (sum((a[i]*yinvpow)*Gi[n+i]) + sum(b[n+i]*Hi[i]) + cL*H + dL*G)
                // Fold INV_EIGHT into scalars; use base_vartime for G (precomputed table)
                for (size_t i = 0; i < n; ++i)
                {
                    const auto scaled = a.container[i] * yinvpow * inv8;
                    std::memcpy(&msm_scalars[i * 32], scaled.data(), 32);
                    msm_points[i] = Gi_p3[n + i];
                }
                for (size_t i = 0; i < n; ++i)
                {
                    const auto s = b.container[n + i] * inv8;
                    std::memcpy(&msm_scalars[(n + i) * 32], s.data(), 32);
                    msm_points[n + i] = Hi_p3[i];
                }
                {
                    const auto s = cL * inv8;
                    std::memcpy(&msm_scalars[2 * n * 32], s.data(), 32);
                }
                msm_points[2 * n] = H_p3;
                const auto base_dL = dL * inv8;

                {
                    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                    ge_multiscalar_mul_base_vartime(&result, msm_scalars.data(), msm_points.data(), total, base_dL.data());
                    L.append(crypto_point_t(result));
                }

                // R = INV_EIGHT * (sum((a[n+i]*ypow)*Gi[i]) + sum(b[i]*Hi[n+i]) + cR*H + dR*G)
                for (size_t i = 0; i < n; ++i)
                {
                    const auto scaled = a.container[n + i] * ypow * inv8;
                    std::memcpy(&msm_scalars[i * 32], scaled.data(), 32);
                    msm_points[i] = Gi_p3[i];
                }
                for (size_t i = 0; i < n; ++i)
                {
                    const auto s = b.container[i] * inv8;
                    std::memcpy(&msm_scalars[(n + i) * 32], s.data(), 32);
                    msm_points[n + i] = Hi_p3[n + i];
                }
                {
                    const auto s = cR * inv8;
                    std::memcpy(&msm_scalars[2 * n * 32], s.data(), 32);
                }
                msm_points[2 * n] = H_p3;
                const auto base_dR = dR * inv8;

                {
                    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                    ge_multiscalar_mul_base_vartime(&result, msm_scalars.data(), msm_points.data(), total, base_dR.data());
                    R.append(crypto_point_t(result));
                }

                tr.update(L.back());

                tr.update(R.back());

                const auto x = tr.challenge();

                if (!x.valid())
                {
                    throw std::runtime_error("x cannot be zero");
                }

                const auto x_inv = x.invert();
                const auto x_yinvpow = x * yinvpow;
                const auto ypow_x_inv = ypow * x_inv;

                // Gi folding via SIMD batch: Gi[i] = x_inv*Gi[i] + (x*yinvpow)*Gi[n+i]
                // _p3 variant writes ge_p3 directly, avoiding expensive tobytes/frombytes round-trip
                ge_double_scalarmult_negate_vartime_batch_ss_p3(
                    &Gi_p3[0], x_inv.data(), &Gi_p3[0], x_yinvpow.data(), &Gi_p3[n], n);

                // Hi folding via SIMD batch: Hi[i] = x*Hi[i] + x_inv*Hi[n+i]
                ge_double_scalarmult_negate_vartime_batch_ss_p3(
                    &Hi_p3[0], x.data(), &Hi_p3[0], x_inv.data(), &Hi_p3[n], n);

                // In-place scalar folding
                for (size_t i = 0; i < n; ++i)
                {
                    const auto ai = a.container[i] * x + a.container[n + i] * ypow_x_inv;
                    const auto bi = b.container[i] * x_inv + b.container[n + i] * x;
                    a.container[i] = ai;
                    b.container[i] = bi;
                }
                a.container.resize(n);
                b.container.resize(n);

                alpha = (dL * x.squared()) + alpha + (dR * x_inv.squared());

                ++round_idx;
            }

        try_again:
            const auto r = crypto_scalar_t::random(), s = crypto_scalar_t::random(), d = crypto_scalar_t::random(),
                       eta = crypto_scalar_t::random();

            if (!r.valid() || !s.valid() || !d.valid() || !eta.valid())
            {
                goto try_again;
            }

            const auto rybsya = (r * y * b[0]) + (s * y * a[0]);

            // A = INV_EIGHT * (r*Gi + s*Hi + rybsya*H + d*G)
            // Single MSM with base (G precomputed table) instead of 2 dbl_mults + point add
            {
                unsigned char a_scalars[3 * 32];
                ge_p3 a_points[3];

                const auto s_r = r * inv8;
                std::memcpy(&a_scalars[0], s_r.data(), 32);
                a_points[0] = Gi_p3[0];

                const auto s_s = s * inv8;
                std::memcpy(&a_scalars[32], s_s.data(), 32);
                a_points[1] = Hi_p3[0];

                const auto s_rybsya = rybsya * inv8;
                std::memcpy(&a_scalars[64], s_rybsya.data(), 32);
                a_points[2] = H_p3;

                const auto base_d = d * inv8;

                ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                ge_multiscalar_mul_base_vartime(&result, a_scalars, a_points, 3, base_d.data());
                A = crypto_point_t(result);
            }

            // B = INV_EIGHT * (r*y*s*H + eta*G) — use base_vartime for G
            {
                unsigned char b_scalars[32];
                ge_p3 b_points[1];

                const auto s_rys = r * y * s * inv8;
                std::memcpy(&b_scalars[0], s_rys.data(), 32);
                b_points[0] = H_p3;

                const auto base_eta = eta * inv8;

                ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                ge_multiscalar_mul_base_vartime(&result, b_scalars, b_points, 1, base_eta.data());
                B = crypto_point_t(result);
            }

            tr.update(A);

            tr.update(B);

            const auto x = tr.challenge();

            if (!x.valid())
            {
                goto try_again;
            }

            r1 = r + (a[0] * x);

            s1 = s + (b[0] * x);

            d1 = eta + (d * x) + (alpha * x.squared());

            done = true;

            return {A, B, r1, s1, d1, L.container, R.container};
        }

      private:
        static crypto_scalar_t weighted_inner_product(
            const crypto_scalar_vector_t &a,
            const crypto_scalar_vector_t &b,
            const crypto_scalar_t &y)
        {
            if (a.size() != b.size())
            {
                throw std::invalid_argument("weighted inner product vectors must be of the same size");
            }

            auto r = Crypto::ZERO;

            auto y_power = y;

            for (size_t i = 0; i < a.size(); ++i)
            {
                r += a[i] * y_power * b[i];

                y_power *= y;
            }

            return r;
        }

        bool done = false;
        scalar_transcript_t tr;
        crypto_point_vector_t Gi, Hi, L, R;
        crypto_point_t A, B;
        crypto_scalar_vector_t a, b;
        crypto_scalar_t alpha, y, r1, s1, d1;
    };

    std::tuple<crypto_bulletproof_plus_t, std::vector<crypto_pedersen_commitment_t>> prove(
        const std::vector<uint64_t> &amounts,
        const std::vector<crypto_blinding_factor_t> &blinding_factors,
        size_t N)
    {
        if (N == 0)
        {
            throw std::range_error("N must be at least 1-bit");
        }

        if (N > 64)
        {
            throw std::range_error("N must not exceed 64-bits");
        }

        if (amounts.size() != blinding_factors.size())
        {
            throw std::runtime_error("amounts and gamma must be the same size");
        }

        if (amounts.empty())
        {
            throw std::runtime_error("amounts is empty");
        }

        for (const auto &blinding_factor : blinding_factors)
        {
            if (!blinding_factor.valid())
            {
                throw std::invalid_argument("blinding factor cannot be zero");
            }
        }

        const auto M = amounts.size();

        N = Crypto::pow2_round(N);

        const auto MN = M * N;

        const auto [Gi, Hi] = generate_exponents(MN);

        const auto one_MN = crypto_scalar_vector_t(MN, Crypto::ONE);

        crypto_point_vector_t V;

        crypto_scalar_vector_t aL, aR;

        for (size_t i = 0; i < M; ++i)
        {
            V.append(Crypto::RingCT::generate_pedersen_commitment(blinding_factors[i], amounts[i]));

            aL.extend(crypto_scalar_t(amounts[i]).to_bits(N));
        }

        aR = aL - one_MN;

    try_again:
        scalar_transcript_t tr(BULLETPROOFS_PLUS_DOMAIN_0);

        const auto alpha = crypto_scalar_t::random();

        if (!alpha.valid())
        {
            goto try_again;
        }

        tr.update(V.container);

        // A = INV_EIGHT * (sum(aL[i]*Gi[i]) + sum(aR[i]*Hi[i]) + alpha*G)
        // Fold INV_EIGHT into scalars to avoid ge_scalarmult_ct
        // Use base_vartime for G (precomputed table)
        const auto inv8 = Crypto::INV_EIGHT;
        crypto_point_t A;
        {
            const size_t total = 2 * MN;
            std::vector<unsigned char> scalars(total * 32);
            std::vector<ge_p3> points(total);

            for (size_t i = 0; i < MN; ++i)
            {
                const auto s = aL[i] * inv8;
                std::memcpy(&scalars[i * 32], s.data(), 32);
                points[i] = Gi[i].p3();
            }
            for (size_t i = 0; i < MN; ++i)
            {
                const auto s = aR[i] * inv8;
                std::memcpy(&scalars[(MN + i) * 32], s.data(), 32);
                points[MN + i] = Hi[i].p3();
            }
            const auto base_s = alpha * inv8;

            ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
            ge_multiscalar_mul_base_vartime(&result, scalars.data(), points.data(), total, base_s.data());
            A = crypto_point_t(result);
        }

        tr.update(A);

        const auto y = tr.challenge();

        if (!y.valid())
        {
            goto try_again;
        }

        tr.update(y);

        const auto z = tr.challenge();

        if (!z.valid())
        {
            goto try_again;
        }

        crypto_scalar_vector_t d;

        for (size_t j = 0; j < M; ++j)
        {
            for (size_t i = 0; i < N; ++i)
            {
                d.append(z.pow(2 * (j + 1)) * powers_of_two[i]);
            }
        }

        const auto aL1 = aL - (one_MN * z);

        const auto yexp = crypto_scalar_vector_t(y.pow_expand(MN, true, false));

        const auto aR1 = aR + (d * yexp) + (one_MN * z);

        auto alpha1 = alpha;

        const auto ypow = y.pow(MN + 1);

        for (size_t j = 0; j < M; ++j)
        {
            alpha1 += z.pow(2 * (j + 1)) * blinding_factors[j] * ypow;
        }

        // we try here as if we fail the challenge in the inner product round then we need to try again
        try
        {
            const auto [A1, B, r1, s1, d1, L, R] = InnerProductRound(Gi, Hi, aL1, aR1, alpha1, y, tr).compute();

            return {crypto_bulletproof_plus_t(A, A1, B, r1, s1, d1, L, R), V.container};
        }
        catch (const std::exception &e)
        {
            PRINTF(e.what())

            goto try_again;
        }
    }

    bool verify(
        const std::vector<crypto_bulletproof_plus_t> &proofs,
        const std::vector<std::vector<crypto_pedersen_commitment_t>> &commitments,
        size_t N)
    {
        if (N == 0)
        {
            throw std::range_error("N must be at least 1-bit");
        }

        if (N > 64)
        {
            throw std::range_error("N must not exceed 64-bits");
        }

        if (proofs.size() != commitments.size())
        {
            return false;
        }

        N = Crypto::pow2_round(N);

        size_t max_M = 0;

        for (const auto &proof : proofs)
        {
            max_M = std::max(max_M, proof.L.size());
        }

        const auto max_MN = size_t(powers_of_two[max_M].to_uint64_t());

        const auto [Gi, Hi] = generate_exponents(max_MN);

        auto G_scalar = Crypto::ZERO, H_scalar = Crypto::ZERO;

        crypto_scalar_vector_t Gi_scalars(max_MN, Crypto::ZERO), Hi_scalars(max_MN, Crypto::ZERO);

        crypto_scalar_vector_t scalars;

        crypto_point_vector_t points;

        for (size_t ii = 0; ii < proofs.size(); ++ii)
        {
            const auto &proof = proofs[ii];

            if (!proof.check_construction())
            {
                return false;
            }

            if (commitments[ii].empty())
            {
                return false;
            }

            scalar_transcript_t tr(BULLETPROOFS_PLUS_DOMAIN_0);

            const auto M = size_t(powers_of_two[proof.L.size()].to_uint64_t()) / N;

            const auto MN = M * N;


            const auto weight = crypto_scalar_t::random();

            tr.update(commitments[ii]);

            tr.update(proof.A);

            const auto y = tr.challenge();

            if (!y.valid())
            {
                return false;
            }

            // value is used multiple times so let's compute it once
            const auto y_powers = y.pow_expand(MN + 2);

            // value is used multiple times so let's compute it once
            const auto &ypow = y_powers[MN + 1];

            tr.update(y);

            const auto z = tr.challenge();

            if (!z.valid())
            {
                return false;
            }

            // value is used multiple times so let's compute it once
            const auto z_powers = z.pow_expand(2 * (M + 1));

            crypto_scalar_vector_t challenges;

            for (size_t j = 0; j < proof.L.size(); ++j)
            {
                tr.update(proof.L[j]);

                tr.update(proof.R[j]);

                const auto challenge = tr.challenge();

                if (!challenge.valid())
                {
                    return false;
                }

                challenges.append(challenge);
            }

            const auto challenges_inv = challenges.invert();

            tr.update(proof.A1);

            tr.update(proof.B);

            const auto x = tr.challenge();

            if (!x.valid())
            {
                return false;
            }

            // value is used multiple times so let's compute it once
            const auto xsquared = x.squared();

            // value is used multiple times so let's compute it once
            const auto xsquare_negated = xsquared.negate();

            const auto y_inv = y.invert();

            // Precompute challenge products via binary expansion,
            // folding y_inv^i into g_products so the inner loop needs fewer mults
            const size_t logMN = challenges.size();

            std::vector<crypto_scalar_t> yinv_g_products(MN), h_products(MN);

            if (logMN > 0)
            {
                yinv_g_products[0] = challenges_inv[logMN - 1];
                yinv_g_products[1] = challenges[logMN - 1] * y_inv;
                h_products[0] = challenges[logMN - 1];
                h_products[1] = challenges_inv[logMN - 1];

                auto y_inv_pow2 = y_inv;

                for (size_t j = 1; j < logMN; ++j)
                {
                    const size_t stride = size_t(1) << (j + 1);
                    const size_t half = stride >> 1;
                    const auto &c = challenges[logMN - 1 - j];
                    const auto &ci = challenges_inv[logMN - 1 - j];

                    y_inv_pow2 = y_inv_pow2.squared();
                    const auto c_yinv = c * y_inv_pow2;

                    for (size_t i = stride - 1; i >= half; --i)
                    {
                        yinv_g_products[i] = yinv_g_products[i - half] * c_yinv;
                        h_products[i] = h_products[i - half] * ci;
                    }

                    for (size_t i = 0; i < half; ++i)
                    {
                        yinv_g_products[i] *= ci;
                        h_products[i] *= c;
                    }
                }
            }
            else
            {
                yinv_g_products[0] = Crypto::ONE;
                h_products[0] = Crypto::ONE;
            }

            // Precompute loop constants, folding weight into binary expansion seeds
            const auto w_r1x = weight * proof.r1 * x;
            const auto w_s1x = weight * proof.s1 * x;
            const auto w_xsq_z = weight * xsquared * z;
            const auto w_xsq = weight * xsquared;

            // Fold w_r1x into g_products and w_s1x into h_products
            // so inner loop has ZERO scalar mults (pure adds)
            for (size_t i = 0; i < MN; ++i)
            {
                yinv_g_products[i] *= w_r1x;
                h_products[i] *= w_s1x;
            }

            // Precompute all subtraction terms
            const auto two_over_y = Crypto::TWO * y_inv;
            const auto two_over_y_powers = two_over_y.pow_expand(N);

            std::vector<crypto_scalar_t> sub_terms(MN);

            for (size_t j = 0; j < M; ++j)
            {
                const auto grp = w_xsq * z_powers[2 * (j + 1)] * y_powers[(M - j) * N];

                for (size_t k = 0; k < N; ++k)
                {
                    sub_terms[j * N + k] = grp * two_over_y_powers[k];
                }
            }

            // Inner loop: ZERO scalar mults — pure additions/subtractions
            for (size_t i = 0; i < MN; ++i)
            {
                Gi_scalars[i] += yinv_g_products[i] + w_xsq_z;

                Hi_scalars[i] += h_products[i] - sub_terms[i] - w_xsq_z;
            }

            // Move ×8 from point-space to scalar-space
            const auto weight8 = weight * Crypto::EIGHT;

            for (size_t j = 0; j < M; ++j)
            {
                scalars.append(weight8 * (xsquare_negated * z_powers[2 * (j + 1)] * ypow));

                points.append(commitments[ii][j]);
            }

            // Compute d_sum analytically: sum(d[i]) = (2^N - 1) * sum(z^(2*(j+1)))
            auto d_sum = Crypto::ZERO;

            for (size_t j = 0; j < M; ++j)
            {
                d_sum += z_powers[2 * (j + 1)];
            }

            d_sum *= Crypto::TWO.pow_sum(N);

            // Sum y^1 + y^2 + ... + y^MN from existing y_powers
            auto y_sum = Crypto::ZERO;

            for (size_t i = 1; i <= MN; ++i)
            {
                y_sum += y_powers[i];
            }

            H_scalar += weight
                        * ((proof.r1 * y * proof.s1)
                           + (xsquared * (((ypow * z) * d_sum) + ((z.squared() - z) * y_sum))));

            G_scalar += weight * proof.d1;

            const auto weight_xsquare_negated8 = weight8 * xsquare_negated;

            scalars.append(weight8 * x.negate());

            points.append(proof.A1);

            scalars.append(weight8.negate());

            points.append(proof.B);

            scalars.append(weight_xsquare_negated8);

            points.append(proof.A);

            for (size_t j = 0; j < proof.L.size(); ++j)
            {
                scalars.append(challenges[j].squared() * weight_xsquare_negated8);

                points.append(proof.L[j]);

                scalars.append(challenges_inv[j].squared() * weight_xsquare_negated8);

                points.append(proof.R[j]);
            }
        }

        scalars.append(G_scalar);

        points.append(Crypto::G);

        scalars.append(H_scalar);

        points.append(Crypto::H);

        for (size_t i = 0; i < max_MN; ++i)
        {
            scalars.append(Gi_scalars[i]);

            points.append(Gi[i]);

            scalars.append(Hi_scalars[i]);

            points.append(Hi[i]);
        }

        return scalars.inner_product(points).empty();
    }

    bool verify(
        const crypto_bulletproof_plus_t &proof,
        const std::vector<crypto_pedersen_commitment_t> &commitments,
        size_t N)
    {
        return verify(
            std::vector<crypto_bulletproof_plus_t>(1, proof),
            std::vector<std::vector<crypto_pedersen_commitment_t>>(1, commitments),
            N);
    }
} // namespace Crypto::RangeProofs::BulletproofsPlus
