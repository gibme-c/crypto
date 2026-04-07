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
 * @file bulletproofs.cpp
 * @brief Original Bulletproofs range proofs with inner product argument (IPA).
 */

// Inspired by the work of Sarang Noether at
// https://github.com/SarangNoether/skunkworks/tree/pybullet

#include <bulletproofs/bulletproofs.h>
#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <ge_double_scalarmult_negate_vartime_batch_ss_p3.h>
#include <ge_multiscalar_mul_vartime.h>
#include <helpers/scalar_transcript_t.h>
#include <mutex>
#include <ringct/ringct.h>
#undef max

static const auto powers_of_two = Crypto::TWO.pow_expand(64);

static std::mutex bulletproofs_mutex;

/**
 * Generates the general bulletproof exponents up through the given count
 * to aid in the speed of proving and verifying, the exponents are cached
 * and if more are requested, then they are generated on demand; otherwise,
 * if less are requested, we supply a slice of the cached entries thus
 * avoiding doing a whole bunch of hashing each generation and verification
 * @param count
 * @return
 */
static std::tuple<point_vector_t, point_vector_t> generate_exponents(size_t count)
{
    std::lock_guard<std::mutex> lock(bulletproofs_mutex);

    // NOTE: Cache is protected by mutex. Under heavy concurrent verification,
    // consider pre-generating to a reasonable maximum at initialization time
    // via Crypto::init() to avoid contention during batch verify.
    static point_vector_t L_cached, R_cached;

    if (count == L_cached.size() && count == R_cached.size())
    {
        return std::make_tuple(L_cached, R_cached);
    }

    if (count < L_cached.size())
    {
        return std::make_tuple(L_cached.slice(0, count), R_cached.slice(0, count));
    }

    auto writer = Serialization::serializer_t();

    for (size_t i = L_cached.size(); i < count; ++i)
    {
        writer.reset();

        writer.uint64(i);

        writer.pod(BULLETPROOFS_DOMAIN_1);

        L_cached.append(hash_t::sha3(writer).point());

        writer.pod(BULLETPROOFS_DOMAIN_2);

        R_cached.append(hash_t::sha3(writer).point());
    }

    return std::make_tuple(L_cached, R_cached);
}

namespace Crypto::RangeProofs::Bulletproofs
{
    /**
     * Helps to calculate an inner product round
     */
    struct InnerProductRound
    {
        InnerProductRound(
            point_vector_t _G,
            point_vector_t _H,
            const point_t &_U,
            scalar_vector_t _a,
            scalar_vector_t _b,
            const scalar_t &_y_inv,
            scalar_transcript_t _tr):
            G(std::move(_G)),
            H(std::move(_H)),
            U(_U),
            a(std::move(_a)),
            b(std::move(_b)),
            y_inv(_y_inv),
            tr(std::move(_tr))
        {
        }

        /**
         * Computes the inner product for the values provided during the initialization of the structure.
         * H generators are kept UNSCALED; y_inv^i factors are applied in scalar space
         * during L/R MSM computation, avoiding expensive scalar-point multiplications.
         * @return {L, R, a, b}
         */
        std::tuple<std::vector<point_t>, std::vector<point_t>, scalar_t, scalar_t> compute()
        {
            if (done)
            {
                return {L.container, R.container, a.container[0], b.container[0]};
            }

            auto n = G.size();

            // Precompute y_inv powers: {1, y_inv, y_inv^2, ..., y_inv^(n-1)}
            const auto yinv_powers = y_inv.pow_expand(n, false, true);

            const auto inv8 = Crypto::INV_EIGHT;

            // Extract raw ge_p3 arrays (avoids repeated .p3() calls and point_t overhead)
            std::vector<ge_p3> G_p3(n), H_p3(n);
            for (size_t i = 0; i < n; ++i)
            {
                G_p3[i] = G.container[i].p3();
            }
            for (size_t i = 0; i < n; ++i)
            {
                H_p3[i] = H.container[i].p3();
            }

            // Pre-allocate MSM buffers for largest round (reused each iteration)
            const size_t max_total = n + 1; // 2*(n/2)+1
            std::vector<unsigned char> msm_scalars(max_total * 32);
            std::vector<ge_p3> msm_points(max_total);
            const auto U_p3 = U.p3();

            while (n > 1)
            {
                n /= 2;

                // Compute scalar inner products directly (no slice needed)
                auto cL = Crypto::ZERO, cR = Crypto::ZERO;
                for (size_t i = 0; i < n; ++i)
                {
                    cL += a.container[i] * b.container[n + i];
                    cR += a.container[n + i] * b.container[i];
                }

                const size_t total = 2 * n + 1;

                // L = INV_EIGHT * (sum(a[i]*G[n+i]) + sum(b[n+i]*yinv[i]*H[i]) + cL*U)
                // Fold INV_EIGHT into scalars to avoid ge_scalarmult_ct
                for (size_t i = 0; i < n; ++i)
                {
                    const auto s = a.container[i] * inv8;
                    std::memcpy(&msm_scalars[i * 32], s.data(), 32);
                    msm_points[i] = G_p3[n + i];
                }
                for (size_t i = 0; i < n; ++i)
                {
                    const auto weighted = b.container[n + i] * yinv_powers[i] * inv8;
                    std::memcpy(&msm_scalars[(n + i) * 32], weighted.data(), 32);
                    msm_points[n + i] = H_p3[i];
                }
                {
                    const auto s = cL * inv8;
                    std::memcpy(&msm_scalars[2 * n * 32], s.data(), 32);
                }
                msm_points[2 * n] = U_p3;

                {
                    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                    ge_multiscalar_mul_vartime(&result, msm_scalars.data(), msm_points.data(), total);
                    L.append(point_t(result));
                }

                // R = INV_EIGHT * (sum(a[n+i]*G[i]) + sum(b[i]*yinv[n+i]*H[n+i]) + cR*U)
                for (size_t i = 0; i < n; ++i)
                {
                    const auto s = a.container[n + i] * inv8;
                    std::memcpy(&msm_scalars[i * 32], s.data(), 32);
                    msm_points[i] = G_p3[i];
                }
                for (size_t i = 0; i < n; ++i)
                {
                    const auto weighted = b.container[i] * yinv_powers[n + i] * inv8;
                    std::memcpy(&msm_scalars[(n + i) * 32], weighted.data(), 32);
                    msm_points[n + i] = H_p3[n + i];
                }
                {
                    const auto s = cR * inv8;
                    std::memcpy(&msm_scalars[2 * n * 32], s.data(), 32);
                }
                msm_points[2 * n] = U_p3;

                {
                    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
                    ge_multiscalar_mul_vartime(&result, msm_scalars.data(), msm_points.data(), total);
                    R.append(point_t(result));
                }

                tr.update(L.back());

                tr.update(R.back());

                const auto x = tr.challenge();

                if (!x.valid())
                {
                    throw std::runtime_error("x cannot be zero");
                }

                const auto x_inv = x.invert();

                // G folding via SIMD batch: G[i] = x_inv*G[i] + x*G[n+i]
                // _p3 variant writes ge_p3 directly, avoiding expensive tobytes/frombytes round-trip
                ge_double_scalarmult_negate_vartime_batch_ss_p3(
                    &G_p3[0], x_inv.data(), &G_p3[0], x.data(), &G_p3[n], n);

                // H folding absorbs y_inv^n: H[i] = x*H[i] + (x_inv*y_inv^n)*H[n+i]
                {
                    const auto x_inv_yinv_n = x_inv * yinv_powers[n];
                    ge_double_scalarmult_negate_vartime_batch_ss_p3(
                        &H_p3[0], x.data(), &H_p3[0], x_inv_yinv_n.data(), &H_p3[n], n);
                }

                // In-place scalar folding
                for (size_t i = 0; i < n; ++i)
                {
                    const auto ai = a.container[i] * x + a.container[n + i] * x_inv;
                    const auto bi = b.container[i] * x_inv + b.container[n + i] * x;
                    a.container[i] = ai;
                    b.container[i] = bi;
                }
                a.container.resize(n);
                b.container.resize(n);
            }

            done = true;

            return {L.container, R.container, a.container[0], b.container[0]};
        }

      private:
        bool done = false;
        point_vector_t G, H;
        point_t U;
        scalar_vector_t a, b;
        scalar_t y_inv;
        scalar_transcript_t tr;
        point_vector_t L, R;
    };

    std::tuple<bulletproof_t, std::vector<pedersen_commitment_t>>
        prove(const std::vector<uint64_t> &amounts, const std::vector<blinding_factor_t> &blinding_factors, size_t N)
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
            throw std::runtime_error("amounts and blinding factors must be the same size");
        }

        if (amounts.empty())
        {
            throw std::runtime_error("amounts is empty");
        }

        for (const auto &blinding_factor : blinding_factors)
        {
            if (!blinding_factor.valid())
            {
                throw std::invalid_argument("invalid blinding factor");
            }
        }

        const auto M = amounts.size();

        N = Crypto::pow2_round(N);

        const auto MN = M * N;

        const auto [Gi, Hi] = generate_exponents(MN);

        point_vector_t V;

        scalar_vector_t aL, aR;

        for (size_t i = 0; i < M; ++i)
        {
            V.append(Crypto::RingCT::generate_pedersen_commitment(blinding_factors[i], amounts[i]));

            aL.extend(scalar_t(amounts[i]).to_bits(N));
        }

        for (const auto &bit : aL.container)
        {
            aR.append(bit - Crypto::ONE);
        }

    retry:
        const auto alpha = scalar_t::random();

        if (!alpha.valid())
        {
            goto retry;
        }

        scalar_transcript_t tr(BULLETPROOFS_DOMAIN_0);

        // Bind N into the Fiat-Shamir transcript so a proof produced under one
        // (silently-normalized) N cannot be replayed against a verifier told a
        // different N out-of-band. BP math is already structurally N-dependent,
        // so this is hygiene / availability -- NOT a soundness gap.
        tr.update(scalar_t(N));

        tr.update(V.container);

        // Precompute ge_p3 points array for A and S MSMs (shared, built once)
        // G is handled via the base_vartime precomputed table, so only 2*MN variable points
        const size_t total_AS = 2 * MN;
        std::vector<ge_p3> as_points(total_AS);
        for (size_t i = 0; i < MN; ++i)
        {
            as_points[i] = Gi[i].p3();
        }
        for (size_t i = 0; i < MN; ++i)
        {
            as_points[MN + i] = Hi[i].p3();
        }

        // A = INV_EIGHT * (sum(aL[i]*Gi[i]) + sum(aR[i]*Hi[i]) + alpha*G)
        // Fold INV_EIGHT into scalars to avoid expensive ge_scalarmult_ct
        // Use base_vartime for G (precomputed table) instead of including G as variable point
        const auto inv8 = Crypto::INV_EIGHT;
        point_t A;
        {
            std::vector<unsigned char> scalars(total_AS * 32);
            for (size_t i = 0; i < MN; ++i)
            {
                const auto s = aL[i] * inv8;
                std::memcpy(&scalars[i * 32], s.data(), 32);
            }
            for (size_t i = 0; i < MN; ++i)
            {
                const auto s = aR[i] * inv8;
                std::memcpy(&scalars[(MN + i) * 32], s.data(), 32);
            }
            const auto base_s = alpha * inv8;

            ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
            ge_multiscalar_mul_base_vartime(&result, scalars.data(), as_points.data(), total_AS, base_s.data());
            A = point_t(result);
        }

        scalar_vector_t sL(scalar_t::random(MN)), sR(scalar_t::random(MN));

        const auto rho = scalar_t::random();

        if (!rho.valid())
        {
            goto retry;
        }

        // S = INV_EIGHT * (sum(sL[i]*Gi[i]) + sum(sR[i]*Hi[i]) + rho*G)
        point_t S;
        {
            std::vector<unsigned char> scalars(total_AS * 32);
            for (size_t i = 0; i < MN; ++i)
            {
                const auto s = sL[i] * inv8;
                std::memcpy(&scalars[i * 32], s.data(), 32);
            }
            for (size_t i = 0; i < MN; ++i)
            {
                const auto s = sR[i] * inv8;
                std::memcpy(&scalars[(MN + i) * 32], s.data(), 32);
            }
            const auto base_s = rho * inv8;

            ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
            ge_multiscalar_mul_base_vartime(&result, scalars.data(), as_points.data(), total_AS, base_s.data());
            S = point_t(result);
        }

        tr.update(A);

        tr.update(S);

        const auto y = tr.challenge();

        if (!y.valid())
        {
            goto retry;
        }

        tr.update(y);

        const auto z = tr.challenge();

        if (!z.valid())
        {
            goto retry;
        }

        const auto y_inv = y.invert();

        const auto y_powers = scalar_vector_t(y.pow_expand(MN));

        const auto l0 = aL - scalar_vector_t(MN, z);

        const auto &l1 = sL;

        scalar_vector_t zeros_twos;

        auto z_cache = z.squared();

        for (size_t j = 0; j < M; ++j)
        {
            for (size_t i = 0; i < N; ++i)
            {
                zeros_twos.append(z_cache * powers_of_two[i]);
            }

            z_cache *= z;
        }

        auto r0 = aR + scalar_vector_t(MN, z);

        r0 = r0 * y_powers;

        r0 = r0 + zeros_twos;

        const auto r1 = y_powers * sR;

        const auto t1 = l0.inner_product(r1) + l1.inner_product(r0);

        const auto t2 = l1.inner_product(r1);

        const auto tau1 = scalar_t::random(), tau2 = scalar_t::random();

        if (!tau1.valid() || !tau2.valid())
        {
            goto retry;
        }

        // Fold INV_EIGHT into dbl_mult scalars: INV_EIGHT*(t1*H + tau1*G) = (t1*inv8)*H + (tau1*inv8)*G
        const auto T1 = (t1 * inv8).dbl_mult(Crypto::H, tau1 * inv8, Crypto::G);

        const auto T2 = (t2 * inv8).dbl_mult(Crypto::H, tau2 * inv8, Crypto::G);

        tr.update(T1);

        tr.update(T2);

        const auto x = tr.challenge();

        if (!x.valid())
        {
            goto retry;
        }

        auto taux = (tau1 * x) + (tau2 * x.squared());

        for (size_t j = 1; j < M + 1; ++j)
        {
            taux += z.pow(1 + j) * blinding_factors[j - 1];
        }

        const auto mu = (x * rho) + alpha;

        const auto l_vec = l0 + (l1 * x);

        const auto r = r0 + (r1 * x);

        const auto t = l_vec.inner_product(r);

        tr.update(taux);

        tr.update(mu);

        tr.update(t);

        const auto x_ip = tr.challenge();

        if (!x_ip.valid())
        {
            goto retry;
        }

        const auto Hx_ip = x_ip * H;

        // we try here as if we fail the challenge in the inner product round then we need to try again
        // Pass unscaled Hi + y_inv; the IPA handles y_inv scaling in scalar space
        // (eliminates MN expensive scalar-point multiplications for Hi_points)
        try
        {
            const auto [L, R, a, b] = InnerProductRound(Gi, Hi, Hx_ip, l_vec, r, y_inv, tr).compute();

            return {bulletproof_t(A, S, T1, T2, taux, mu, L, R, a, b, t), V.container};
        }
        catch (const std::exception &)
        {
            goto retry;
        }
    }

    bool verify(
        const std::vector<bulletproof_t> &proofs,
        const std::vector<std::vector<pedersen_commitment_t>> &commitments,
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

        auto y0 = Crypto::ZERO, y1 = Crypto::ZERO, z1 = Crypto::ZERO, z3 = Crypto::ZERO;

        std::vector<scalar_t> Gi_scalars(max_MN, Crypto::ZERO), Hi_scalars(max_MN, Crypto::ZERO);

        scalar_vector_t scalars;

        point_vector_t points;

        // Batch verification: accumulate all proofs into a single MSM check
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

            const auto M = size_t(powers_of_two[proof.L.size()].to_uint64_t()) / N;

            const auto MN = M * N;

            const auto weight_y = scalar_t::random(), weight_z = scalar_t::random();

            scalar_transcript_t tr(BULLETPROOFS_DOMAIN_0);

            // Bind N (already pow2_round-normalized at the top of verify) into
            // the transcript before any commitment, mirroring the prover.
            tr.update(scalar_t(N));

            tr.update(commitments[ii]);

            tr.update(proof.A);

            tr.update(proof.S);

            const auto y = tr.challenge();

            if (!y.valid())
            {
                return false;
            }

            const auto y_powers = y.pow_expand(MN);

            const auto y_inv = y.invert();

            tr.update(y);

            const auto z = tr.challenge();

            if (!z.valid())
            {
                return false;
            }

            const auto z_powers = z.pow_expand(M + 3);

            tr.update(proof.T1);

            tr.update(proof.T2);

            const auto x = tr.challenge();

            if (!x.valid())
            {
                return false;
            }

            tr.update(proof.taux);

            tr.update(proof.mu);

            tr.update(proof.t);

            const auto x_ip = tr.challenge();

            if (!x_ip.valid())
            {
                return false;
            }

            y0 += (proof.taux * weight_y);

            auto k = (z - z.squared()) * scalar_vector_t(y_powers).sum();

            for (size_t j = 1; j < M + 1; ++j)
            {
                k -= (z_powers[j + 2] * Crypto::TWO.pow_sum(N));
            }

            y1 += (proof.t - k) * weight_y;

            // Move ×8 from point-space to scalar-space: (s * 8) * P_stored = s * P_actual
            // check_construction() already validates all proof points (on-curve + non-identity)
            // Random weighting prevents small-subgroup exploitation
            const auto weight_y8 = weight_y * Crypto::EIGHT;
            const auto weight_z8 = weight_z * Crypto::EIGHT;

            for (size_t j = 0; j < M; ++j)
            {
                scalars.append(z_powers[j + 2] * weight_y8);

                points.append(commitments[ii][j]);
            }

            scalars.append(x * weight_y8);

            points.append(proof.T1);

            scalars.append(x.squared() * weight_y8);

            points.append(proof.T2);

            scalars.append(weight_z8);

            points.append(proof.A);

            scalars.append(x * weight_z8);

            points.append(proof.S);

            scalar_vector_t challenges;

            for (size_t i = 0; i < proof.L.size(); ++i)
            {
                tr.update(proof.L[i]);

                tr.update(proof.R[i]);

                const auto challenge = tr.challenge();

                if (!challenge.valid())
                {
                    return false;
                }

                challenges.append(challenge);
            }

            const auto challenges_inv = challenges.invert();

            // Precompute challenge products via binary expansion,
            // folding y_inv^i into h_products AND weight constants into seeds
            // so the inner loop needs ZERO scalar multiplications (pure adds)
            const size_t logMN = challenges.size();

            const auto g_wz = proof.g * weight_z;
            const auto z_wz = z * weight_z;
            const auto h_wz = proof.h * weight_z;

            std::vector<scalar_t> g_products(MN), yinv_h_products(MN);

            if (logMN > 0)
            {
                // Fold g_wz into g_products seeds, h_wz into h_products seeds
                g_products[0] = challenges_inv[logMN - 1] * g_wz;
                g_products[1] = challenges[logMN - 1] * g_wz;
                yinv_h_products[0] = challenges[logMN - 1] * h_wz;
                yinv_h_products[1] = challenges_inv[logMN - 1] * y_inv * h_wz;

                auto y_inv_pow2 = y_inv;

                for (size_t j = 1; j < logMN; ++j)
                {
                    const size_t stride = size_t(1) << (j + 1);
                    const size_t half = stride >> 1;
                    const auto &c = challenges[logMN - 1 - j];
                    const auto &ci = challenges_inv[logMN - 1 - j];

                    y_inv_pow2 = y_inv_pow2.squared();
                    const auto ci_yinv = ci * y_inv_pow2;

                    for (size_t i = stride - 1; i >= half; --i)
                    {
                        g_products[i] = g_products[i - half] * c;
                        yinv_h_products[i] = yinv_h_products[i - half] * ci_yinv;
                    }

                    for (size_t i = 0; i < half; ++i)
                    {
                        g_products[i] *= ci;
                        yinv_h_products[i] *= c;
                    }
                }
            }
            else
            {
                g_products[0] = g_wz;
                yinv_h_products[0] = h_wz;
            }

            // Precompute all subtraction terms: wz_group[j] * two_yinv_powers[k]
            const auto two_yinv = Crypto::TWO * y_inv;
            const auto two_yinv_powers = two_yinv.pow_expand(N);
            const auto yinv_N = y_inv.pow(N);

            std::vector<scalar_t> sub_terms(MN);
            {
                auto yinv_jN = Crypto::ONE;

                for (size_t j = 0; j < M; ++j)
                {
                    const auto wz_grp = weight_z * z_powers[2 + j] * yinv_jN;

                    for (size_t d = 0; d < N; ++d)
                    {
                        sub_terms[j * N + d] = wz_grp * two_yinv_powers[d];
                    }

                    yinv_jN *= yinv_N;
                }
            }

            // Inner loop: ZERO scalar mults — pure additions/subtractions
            for (size_t i = 0; i < MN; ++i)
            {
                Gi_scalars[i] += g_products[i] + z_wz;

                Hi_scalars[i] += yinv_h_products[i] - z_wz - sub_terms[i];
            }

            z1 += proof.mu * weight_z;

            for (size_t i = 0; i < proof.L.size(); ++i)
            {
                scalars.append(challenges[i].squared() * weight_z8);

                points.append(proof.L[i]);

                scalars.append(challenges_inv[i].squared() * weight_z8);

                points.append(proof.R[i]);
            }

            z3 += (proof.t - proof.g * proof.h) * x_ip * weight_z;
        }

        scalars.append(y0.negate() - z1);

        points.append(Crypto::G);

        scalars.append(y1.negate() + z3);

        points.append(Crypto::H);

        for (size_t i = 0; i < max_MN; ++i)
        {
            scalars.append(Gi_scalars[i].negate());

            points.append(Gi[i]);

            scalars.append(Hi_scalars[i].negate());

            points.append(Hi[i]);
        }

        // Final MSM: if all proofs are valid, the linear combination equals the identity point
        return scalars.inner_product(points).empty();
    }

    bool verify(const bulletproof_t &proof, const std::vector<pedersen_commitment_t> &commitments, size_t N)
    {
        return verify(
            std::vector<bulletproof_t>(1, proof), std::vector<std::vector<pedersen_commitment_t>>(1, commitments), N);
    }
} // namespace Crypto::RangeProofs::Bulletproofs
