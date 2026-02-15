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
 * @file bulletproofspp.cpp
 * @brief Bulletproofs++ reciprocal-argument range proofs with WNLA inner proof system.
 */

// Based on ePrint 2022/510 (Bulletproofs++)
// Reference: distributed-lab/bp-pp Rust implementation

#include <crypto_common.h>
#include <crypto_constants.h>
#include <ge_double_scalarmult_negate_vartime_batch_ss_p3.h>
#include <ge_multiscalar_mul_vartime.h>
#include <helpers/scalar_transcript_t.h>
#include <mutex>
#include <proofs/bulletproofspp.h>
#include <proofs/ringct.h>

// ============================================================================
// Per-value constants for reciprocal range proof (base-16, 16 hex digits)
// ============================================================================
static constexpr size_t DIM_ND = 16; // number of hex digits per value
static constexpr size_t DIM_NP = 16; // base (hex)

// ============================================================================
// Generator caching (grows on demand for M > 1)
// ============================================================================
static std::mutex bpp_mutex;

static std::tuple<crypto_point_vector_t, crypto_point_vector_t> generate_exponents(
    size_t g_count, size_t h_count)
{
    std::scoped_lock lock(bpp_mutex);

    static crypto_point_vector_t g_cached, h_cached;

    if (g_count <= g_cached.size() && h_count <= h_cached.size())
    {
        if (g_count == g_cached.size() && h_count == h_cached.size())
            return {g_cached, h_cached};
        return {g_cached.slice(0, g_count), h_cached.slice(0, h_count)};
    }

    auto writer = Serialization::serializer_t();

    for (size_t i = g_cached.size(); i < g_count; ++i)
    {
        writer.reset();
        writer.uint64(i);
        writer.pod(BULLETPROOFS_PP_DOMAIN_1);
        g_cached.append(crypto_hash_t::sha3(writer).point());
    }

    for (size_t i = h_cached.size(); i < h_count; ++i)
    {
        writer.reset();
        writer.uint64(i);
        writer.pod(BULLETPROOFS_PP_DOMAIN_2);
        h_cached.append(crypto_hash_t::sha3(writer).point());
    }

    return {g_cached.slice(0, g_count), h_cached.slice(0, h_count)};
}

// ============================================================================
// Helper: weighted inner product <a, b>_mu = sum_i(mu^(i+1) * a[i] * b[i])
// ============================================================================
static crypto_scalar_t weight_inner_product(
    const std::vector<crypto_scalar_t> &a,
    const std::vector<crypto_scalar_t> &b,
    const crypto_scalar_t &mu)
{
    auto result = Crypto::ZERO;
    auto exp = Crypto::ONE;
    const auto sz = (std::min)(a.size(), b.size());
    for (size_t i = 0; i < sz; ++i)
    {
        exp *= mu;
        result += a[i] * b[i] * exp;
    }
    return result;
}

// ============================================================================
// Helper: scalar-vector inner product <a, b> = sum(a[i]*b[i])
// ============================================================================
static crypto_scalar_t dot(
    const std::vector<crypto_scalar_t> &a,
    const std::vector<crypto_scalar_t> &b)
{
    auto result = Crypto::ZERO;
    const auto sz = (std::min)(a.size(), b.size());
    for (size_t i = 0; i < sz; ++i)
    {
        result += a[i] * b[i];
    }
    return result;
}

// ============================================================================
// Helper: MSM using raw ge_p3 arrays, returns crypto_point_t
// ============================================================================
static crypto_point_t msm(
    const std::vector<crypto_scalar_t> &scalars,
    const std::vector<ge_p3> &points,
    size_t n)
{
    std::vector<unsigned char> s(n * 32);
    for (size_t i = 0; i < n; ++i)
    {
        std::memcpy(&s[i * 32], scalars[i].data(), 32);
    }
    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
    ge_multiscalar_mul_vartime(&result, s.data(), points.data(), n);
    return crypto_point_t(result);
}

// MSM with base point G: result = base_scalar*G + sum(scalars[i]*points[i])
static crypto_point_t msm_base(
    const std::vector<crypto_scalar_t> &scalars,
    const std::vector<ge_p3> &points,
    size_t n,
    const crypto_scalar_t &base_scalar)
{
    std::vector<unsigned char> s(n * 32);
    for (size_t i = 0; i < n; ++i)
    {
        std::memcpy(&s[i * 32], scalars[i].data(), 32);
    }
    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
    ge_multiscalar_mul_base_vartime(&result, s.data(), points.data(), n, base_scalar.data());
    return crypto_point_t(result);
}

// ============================================================================
// Helper: point-vector inner product <scalars, points> via MSM
// ============================================================================
static crypto_point_t point_inner_product(
    const std::vector<crypto_scalar_t> &scalars,
    const std::vector<ge_p3> &points,
    size_t n)
{
    if (n == 0) return Crypto::Z;
    return msm(scalars, points, n);
}

namespace Crypto::RangeProofs::BulletproofsPP
{
    // ========================================================================
    // PROVE
    // ========================================================================
    std::tuple<crypto_bulletproof_pp_t, std::vector<crypto_pedersen_commitment_t>> prove(
        const std::vector<uint64_t> &amounts,
        const std::vector<crypto_blinding_factor_t> &blinding_factors,
        size_t N)
    {
        if (N == 0 || N > 64)
        {
            throw std::range_error("N must be between 1 and 64");
        }

        // Validate amounts fit in N bits
        for (const auto &amount : amounts)
        {
            if (N < 64 && amount >= (1ULL << N))
            {
                throw std::range_error("amount exceeds range for N bits");
            }
        }

        if (amounts.size() != blinding_factors.size() || amounts.empty())
        {
            throw std::runtime_error("amounts and blinding_factors must be the same non-empty size");
        }

        for (const auto &bf : blinding_factors)
        {
            if (!bf.valid())
            {
                throw std::invalid_argument("blinding factor cannot be zero");
            }
        }

        const auto M = amounts.size();
        const auto M_pad = Crypto::pow2_round(M);

        // Pad amounts and blindings to M_pad
        std::vector<uint64_t> amounts_pad(M_pad, 0);
        std::vector<crypto_blinding_factor_t> blindings_pad(M_pad, Crypto::ZERO);
        for (size_t i = 0; i < M; ++i)
        {
            amounts_pad[i] = amounts[i];
            blindings_pad[i] = blinding_factors[i];
        }

        // Runtime dimensions
        const size_t ND_TOTAL = M_pad * DIM_ND;   // total digits
        const size_t NM_TOTAL = ND_TOTAL;          // multiplier gates
        const size_t NV_TOTAL = M_pad * 17;        // witness slots (16 multiplicities + 1 zero per value)
        const size_t G_VEC_FULL = ND_TOTAL;
        const size_t H_VEC_FULL = 2 * ND_TOTAL;    // next_pow2(9 + NV_TOTAL) = 2*M_pad*16

        const auto [g_vec, h_vec] = generate_exponents(G_VEC_FULL, H_VEC_FULL);

        // Extract ge_p3 arrays for MSM
        std::vector<ge_p3> g_p3(G_VEC_FULL), h_p3(H_VEC_FULL);
        for (size_t i = 0; i < G_VEC_FULL; ++i) g_p3[i] = g_vec[i].p3();
        for (size_t i = 0; i < H_VEC_FULL; ++i) h_p3[i] = h_vec[i].p3();
        const auto inv8 = Crypto::INV_EIGHT;

        // Generate commitments V_j = amount_j*G + blinding_j*h_vec[0]
        std::vector<crypto_point_t> V_all(M_pad);
        for (size_t j = 0; j < M_pad; ++j)
            V_all[j] = crypto_scalar_t(amounts_pad[j]) * Crypto::G + blindings_pad[j] * h_vec[0];

    try_again:
        // ---- Transcript: bind all commitments, get challenge e ----
        scalar_transcript_t tr(BULLETPROOFS_PP_DOMAIN_0);
        for (size_t j = 0; j < M_pad; ++j)
            tr.update(V_all[j]);

        const auto e = tr.challenge();
        if (!e.valid()) goto try_again;

        // ---- Digit decomposition (base-16) for all values ----
        std::vector<crypto_scalar_t> digits(ND_TOTAL);
        for (size_t j = 0; j < M_pad; ++j)
        {
            auto val = amounts_pad[j];
            for (size_t i = 0; i < DIM_ND; ++i)
            {
                digits[j * DIM_ND + i] = crypto_scalar_t(val & 0xFu);
                val >>= 4;
            }
        }

        // ---- Multiplicities per value: count of each digit value ----
        std::vector<crypto_scalar_t> multiplicities(M_pad * DIM_NP, Crypto::ZERO);
        for (size_t j = 0; j < M_pad; ++j)
        {
            auto val = amounts_pad[j];
            for (size_t i = 0; i < DIM_ND; ++i)
            {
                const auto digit = val & 0xFu;
                multiplicities[j * DIM_NP + digit] = multiplicities[j * DIM_NP + digit] + Crypto::ONE;
                val >>= 4;
            }
        }

        // ---- Reciprocals: r[i] = 1/(digits[i] + e) ---- (batch inversion)
        std::vector<crypto_scalar_t> reciprocals(ND_TOTAL);
        {
            std::vector<crypto_scalar_t> sums(ND_TOTAL);
            for (size_t i = 0; i < ND_TOTAL; ++i)
            {
                sums[i] = digits[i] + e;
                if (!sums[i].valid()) goto try_again;
            }
            const auto inv = crypto_scalar_vector_t(std::move(sums)).invert();
            for (size_t i = 0; i < ND_TOTAL; ++i)
                reciprocals[i] = inv[i];
        }

        // ---- Pole commitment R = r_blind * h[0] + sum_j <reciprocals_j, h[9+j*17:9+j*17+16]> ----
        const auto r_blind = crypto_scalar_t::random();
        if (!r_blind.valid()) goto try_again;

        crypto_point_t R;
        {
            const size_t total = 1 + ND_TOTAL;
            std::vector<crypto_scalar_t> r_scalars(total);
            std::vector<ge_p3> r_points(total);
            r_scalars[0] = r_blind * inv8;
            r_points[0] = h_p3[0];
            for (size_t j = 0; j < M_pad; ++j)
            {
                for (size_t i = 0; i < DIM_ND; ++i)
                {
                    const size_t si = 1 + j * DIM_ND + i;
                    r_scalars[si] = reciprocals[j * DIM_ND + i] * inv8;
                    r_points[si] = h_p3[9 + j * 17 + i];
                }
            }
            R = msm(r_scalars, r_points, total);
        }

        // ---- Wire witnesses ----
        const auto &nl = digits;
        const auto &nr = reciprocals;
        std::vector<crypto_scalar_t> ll_(NV_TOTAL, Crypto::ZERO);
        for (size_t j = 0; j < M_pad; ++j)
            for (size_t i = 0; i < DIM_NP; ++i)
                ll_[j * 17 + i] = multiplicities[j * DIM_NP + i];

        // ---- Random blindings (always 9 elements, independent of M) ----
        // ro[9]: [r,r,r,r,0,r,r,r,0]
        // rl[9]: [r,r,r,0,r,r,r,0,0]
        // rr[9]: [r,r,0,r,r,r,0,0,0]
        std::vector<crypto_scalar_t> ro(9, Crypto::ZERO), rl(9, Crypto::ZERO), rr(9, Crypto::ZERO);
        {
            auto randoms = crypto_scalar_t::random(18);
            size_t ri = 0;
            ro[0] = randoms[ri++]; ro[1] = randoms[ri++]; ro[2] = randoms[ri++]; ro[3] = randoms[ri++];
            ro[5] = randoms[ri++]; ro[6] = randoms[ri++]; ro[7] = randoms[ri++];
            rl[0] = randoms[ri++]; rl[1] = randoms[ri++]; rl[2] = randoms[ri++];
            rl[4] = randoms[ri++]; rl[5] = randoms[ri++]; rl[6] = randoms[ri++];
            rr[0] = randoms[ri++]; rr[1] = randoms[ri++];
            rr[3] = randoms[ri++]; rr[4] = randoms[ri++]; rr[5] = randoms[ri++];
        }

        // ---- Circuit commitments via MSM ----
        // C_o = INV_EIGHT * sum(ro[i]*h[i] for non-zero ro)  (lo=0, no=0)
        crypto_point_t C_o;
        {
            std::vector<crypto_scalar_t> s(7);
            std::vector<ge_p3> p(7);
            size_t idx = 0;
            for (size_t i : {0,1,2,3,5,6,7})
            {
                s[idx] = ro[i] * inv8;
                p[idx] = h_p3[i];
                idx++;
            }
            C_o = msm(s, p, 7);
        }

        // C_l = INV_EIGHT * (<h, [rl | ll]> + <g, nl>)
        crypto_point_t C_l;
        {
            const size_t total = 6 + NV_TOTAL + ND_TOTAL;
            std::vector<crypto_scalar_t> s(total);
            std::vector<ge_p3> p(total);
            size_t idx = 0;
            for (size_t i : {0,1,2,4,5,6})
            {
                s[idx] = rl[i] * inv8;
                p[idx] = h_p3[i];
                idx++;
            }
            for (size_t i = 0; i < NV_TOTAL; ++i)
            {
                s[idx] = ll_[i] * inv8;
                p[idx] = h_p3[9 + i];
                idx++;
            }
            for (size_t i = 0; i < ND_TOTAL; ++i)
            {
                s[idx] = nl[i] * inv8;
                p[idx] = g_p3[i];
                idx++;
            }
            C_l = msm(s, p, total);
        }

        // C_r = INV_EIGHT * (sum(rr[i]*h[i]) + sum(nr[i]*g[i]))  (lr=0)
        crypto_point_t C_r;
        {
            const size_t total = 5 + ND_TOTAL;
            std::vector<crypto_scalar_t> s(total);
            std::vector<ge_p3> p(total);
            size_t idx = 0;
            for (size_t i : {0,1,3,4,5})
            {
                s[idx] = rr[i] * inv8;
                p[idx] = h_p3[i];
                idx++;
            }
            for (size_t i = 0; i < ND_TOTAL; ++i)
            {
                s[idx] = nr[i] * inv8;
                p[idx] = g_p3[i];
                idx++;
            }
            C_r = msm(s, p, total);
        }

        // ---- Transcript: get circuit challenges ----
        tr.update(C_l);
        tr.update(C_r);
        tr.update(C_o);
        for (size_t j = 0; j < M_pad; ++j)
            tr.update(V_all[j]);

        const auto rho = tr.challenge();
        if (!rho.valid()) goto try_again;
        const auto lambda = tr.challenge();
        if (!lambda.valid()) goto try_again;
        const auto beta = tr.challenge();
        if (!beta.valid()) goto try_again;
        const auto delta = tr.challenge();
        if (!delta.valid()) goto try_again;

        const auto mu = rho * rho;

        // ---- Compute lambda powers for M_pad values ----
        // Need lambda^0 through lambda^(M_pad*17) for per-value coefficients
        const size_t lambda_len = M_pad * 17 + 1;
        std::vector<crypto_scalar_t> lambda_vec(lambda_len);
        {
            auto lp = Crypto::ONE;
            for (size_t i = 0; i < lambda_len; ++i)
            {
                lambda_vec[i] = lp;
                lp *= lambda;
            }
        }

        // Per-value linear combination coefficients: lcc[idx] = lambda^(17*idx)
        // Per-value lambda sums: lambda_sum_vec[idx] = sum_{k=1}^{16} lambda^(idx*17+k)
        std::vector<crypto_scalar_t> lcc(M_pad), lambda_sum_vec(M_pad);
        for (size_t idx = 0; idx < M_pad; ++idx)
        {
            lcc[idx] = lambda_vec[17 * idx];
            auto ls_acc = Crypto::ZERO;
            for (size_t k = 1; k <= DIM_ND; ++k)
                ls_acc += lambda_vec[idx * 17 + k];
            lambda_sum_vec[idx] = ls_acc;
        }

        // Batch invert mu and beta (2 inversions → 1 batch)
        const auto batch_inv_2 = crypto_scalar_vector_t(std::vector<crypto_scalar_t>{mu, beta}).invert();
        const auto mu_inv = batch_inv_2[0];
        const auto beta_inv = batch_inv_2[1];

        // mu_inv_pow[j] = mu^-(j+1) for j=0..NM_TOTAL-1
        std::vector<crypto_scalar_t> mu_inv_pow(NM_TOTAL);
        {
            auto mip = Crypto::ONE;
            for (size_t i = 0; i < NM_TOTAL; ++i)
            {
                mip *= mu_inv;
                mu_inv_pow[i] = mip;
            }
        }

        // ---- Compute constraint vectors for M_pad values ----
        // c_nL[idx*16+d] = -lcc[idx] * 16^d * mu^-(idx*16+d+1)
        std::vector<crypto_scalar_t> c_nL(NM_TOTAL);
        {
            const auto base = crypto_scalar_t(DIM_NP);
            for (size_t idx = 0; idx < M_pad; ++idx)
            {
                auto base_pow = Crypto::ONE;
                for (size_t d = 0; d < DIM_ND; ++d)
                {
                    const size_t gi = idx * DIM_ND + d;
                    c_nL[gi] = (lcc[idx] * base_pow).negate() * mu_inv_pow[gi];
                    base_pow *= base;
                }
            }
        }

        // c_nR[idx*16+d] = (lambda_sum_idx - lambda^(idx*17+d+1)) * mu^-(idx*16+d+1) + e
        std::vector<crypto_scalar_t> c_nR(NM_TOTAL);
        for (size_t idx = 0; idx < M_pad; ++idx)
        {
            for (size_t d = 0; d < DIM_ND; ++d)
            {
                const size_t gi = idx * DIM_ND + d;
                c_nR[gi] = (lambda_sum_vec[idx] - lambda_vec[idx * 17 + d + 1]) * mu_inv_pow[gi] + e;
            }
        }

        // c_lL[idx*17+j] = -lambda_sum_idx / (e+j) for j<16, 0 for j=16
        // Batch invert (e+j) for j=0..15 (shared across all values)
        std::vector<crypto_scalar_t> c_lL(NV_TOTAL, Crypto::ZERO);
        {
            std::vector<crypto_scalar_t> e_plus(DIM_NP);
            for (size_t j = 0; j < DIM_NP; ++j)
                e_plus[j] = e + crypto_scalar_t(j);
            const auto inv = crypto_scalar_vector_t(std::move(e_plus)).invert();
            for (size_t idx = 0; idx < M_pad; ++idx)
            {
                const auto neg_ls = lambda_sum_vec[idx].negate();
                for (size_t j = 0; j < DIM_NP; ++j)
                    c_lL[idx * 17 + j] = neg_ls * inv[j];
            }
        }

        // c_l0[idx*17+j] = lambda^(idx*17+j+1) for j=0..15, 0 for j=16
        std::vector<crypto_scalar_t> c_l0(NV_TOTAL, Crypto::ZERO);
        for (size_t idx = 0; idx < M_pad; ++idx)
            for (size_t j = 0; j < DIM_ND; ++j)
                c_l0[idx * 17 + j] = lambda_vec[idx * 17 + j + 1];

        // ---- Random shift polynomial blindings ----
        auto ls = crypto_scalar_t::random(NV_TOTAL);
        auto ns = crypto_scalar_t::random(NM_TOTAL);

        // ---- Compute v_1, rv (value contributions) ----
        const auto two = crypto_scalar_t(2);
        // v_1[idx*17+d] = 2*reciprocals[idx*16+d] for d<16, 0 for d=16
        // Note: lcc[j] weighting is NOT in v_1 because R is committed before lambda is known.
        // The lcc factor enters through c_l0 (which has lcc implicitly via lambda powers).
        std::vector<crypto_scalar_t> v_1(NV_TOTAL, Crypto::ZERO);
        for (size_t idx = 0; idx < M_pad; ++idx)
            for (size_t d = 0; d < DIM_ND; ++d)
                v_1[idx * 17 + d] = two * reciprocals[idx * DIM_ND + d];

        // rv[0] = 2 * (r_blind + sum_j(lcc[j] * blinding_j))
        std::vector<crypto_scalar_t> rv(9, Crypto::ZERO);
        {
            auto blind_sum = r_blind;
            for (size_t j = 0; j < M_pad; ++j)
                blind_sum += lcc[j] * blindings_pad[j];
            rv[0] = two * blind_sum;
        }

        // ---- Polynomial coefficients f[0..7] ----
        std::vector<crypto_scalar_t> f(8, Crypto::ZERO);

        // Loop 1 (ns-based): weighted inner products over NM_TOTAL
        {
            auto mu_pow = Crypto::ONE;
            auto ns_ns = Crypto::ZERO;
            auto ns_nl = Crypto::ZERO, ns_cnR = Crypto::ZERO;
            auto ns_nr = Crypto::ZERO, ns_cnL = Crypto::ZERO;
            for (size_t i = 0; i < NM_TOTAL; ++i)
            {
                mu_pow *= mu;
                const auto ns_mu = ns[i] * mu_pow;
                ns_ns += ns[i] * ns_mu;
                ns_nl += ns_mu * nl[i];
                ns_cnR += ns_mu * c_nR[i];
                ns_nr += ns_mu * nr[i];
                ns_cnL += ns_mu * c_nL[i];
            }
            f[0] = ns_ns.negate();
            f[2] = (two * (ns_nl + ns_cnR)).negate();
            f[3] = two * (ns_nr + ns_cnL);
        }

        // Loop 2 (nl/nr-based) over NM_TOTAL
        {
            auto mu_pow = Crypto::ONE;
            auto nl_nl = Crypto::ZERO, nl_cnR = Crypto::ZERO;
            auto nr_nr = Crypto::ZERO, nr_cnL = Crypto::ZERO;
            for (size_t i = 0; i < NM_TOTAL; ++i)
            {
                mu_pow *= mu;
                const auto nl_mu = nl[i] * mu_pow;
                const auto nr_mu = nr[i] * mu_pow;
                nl_nl += nl[i] * nl_mu;
                nl_cnR += nl_mu * c_nR[i];
                nr_nr += nr[i] * nr_mu;
                nr_cnL += nr_mu * c_nL[i];
            }
            f[4] = (nl_nl + two * nl_cnR).negate();
            f[5] = (nr_nr + two * nr_cnL).negate();
        }

        // Unweighted dot products over NV_TOTAL
        {
            auto f1_acc = Crypto::ZERO;
            auto f3_clL_ls = Crypto::ZERO, f3_cl0_ll = Crypto::ZERO;
            auto f6_acc = Crypto::ZERO;
            for (size_t i = 0; i < NV_TOTAL; ++i)
            {
                f1_acc += c_l0[i] * ls[i];
                f3_clL_ls += c_lL[i] * ls[i];
                f3_cl0_ll += c_l0[i] * ll_[i];
                f6_acc += c_lL[i] * v_1[i];
            }
            f[1] = f1_acc;
            f[3] = f[3] + two * f3_clL_ls + f3_cl0_ll;
            f[6] = two * f6_acc;
        }

        // ---- Compute rs[9] from f and random blindings ----
        std::vector<crypto_scalar_t> rs(9);
        rs[0] = f[1] + ro[1] * delta * beta;
        rs[1] = f[0] * beta_inv;
        rs[2] = (ro[0] * delta + f[2]) * beta_inv - rl[1];
        rs[3] = (f[3] - rl[0]) * beta_inv + ro[2] * delta + rr[1];
        rs[4] = (f[4] + rr[0]) * beta_inv + ro[3] * delta - rl[2];
        rs[5] = (rv[0] * beta_inv).negate();
        rs[6] = f[5] * beta_inv + ro[5] * delta + rr[3] - rl[4];
        rs[7] = f[6] * beta_inv + rr[4] + ro[6] * delta - rl[5];
        rs[8] = f[7] * beta_inv + ro[7] * delta - rl[6] + rr[5];

        // ---- Shift commitment C_s = INV_EIGHT * (<h, [rs | ls]> + <g, ns>) ----
        crypto_point_t C_s;
        {
            const size_t total = 9 + NV_TOTAL + NM_TOTAL;
            std::vector<crypto_scalar_t> s(total);
            std::vector<ge_p3> p(total);
            for (size_t i = 0; i < 9; ++i)
            {
                s[i] = rs[i] * inv8;
                p[i] = h_p3[i];
            }
            for (size_t i = 0; i < NV_TOTAL; ++i)
            {
                s[9 + i] = ls[i] * inv8;
                p[9 + i] = h_p3[9 + i];
            }
            for (size_t i = 0; i < NM_TOTAL; ++i)
            {
                s[9 + NV_TOTAL + i] = ns[i] * inv8;
                p[9 + NV_TOTAL + i] = g_p3[i];
            }
            C_s = msm(s, p, total);
        }

        // ---- Transcript: get tau ----
        tr.update(C_s);
        const auto tau = tr.challenge();
        if (!tau.valid()) goto try_again;

        const auto tau2 = tau * tau;
        const auto tau3 = tau2 * tau;

        // ---- Build WNLA rho/mu sequences dynamically ----
        // Determine number of WNLA rounds from vector sizes
        size_t num_wnla_rounds = 0;
        {
            size_t l_sz = H_VEC_FULL, n_sz = G_VEC_FULL;
            while (l_sz + n_sz >= 6) { l_sz /= 2; n_sz /= 2; ++num_wnla_rounds; }
        }

        // WNLA rho sequence: rho, mu, mu^2, mu^4, mu^8, ...
        // WNLA mu^2 sequence: mu^2, mu^4, mu^8, mu^16, ...
        std::vector<crypto_scalar_t> wnla_rho_fwd(num_wnla_rounds);
        std::vector<crypto_scalar_t> wnla_mu2_vec(num_wnla_rounds);
        {
            wnla_rho_fwd[0] = rho;
            auto mu_sq = mu;
            for (size_t r = 1; r < num_wnla_rounds; ++r)
            {
                wnla_rho_fwd[r] = mu_sq;
                mu_sq = mu_sq * mu_sq;
            }
            mu_sq = mu * mu;
            for (size_t r = 0; r < num_wnla_rounds; ++r)
            {
                wnla_mu2_vec[r] = mu_sq;
                mu_sq = mu_sq * mu_sq;
            }
        }

        // Batch invert tau and all WNLA rho values
        std::vector<crypto_scalar_t> wnla_rho_inv(num_wnla_rounds);
        crypto_scalar_t tau_inv;
        {
            std::vector<crypto_scalar_t> to_inv;
            to_inv.reserve(1 + num_wnla_rounds);
            to_inv.push_back(tau);
            for (size_t r = 0; r < num_wnla_rounds; ++r)
                to_inv.push_back(wnla_rho_fwd[r]);
            const auto inv_batch = crypto_scalar_vector_t(std::move(to_inv)).invert();
            tau_inv = inv_batch[0];
            for (size_t r = 0; r < num_wnla_rounds; ++r)
                wnla_rho_inv[r] = inv_batch[1 + r];
        }

        // ---- Assemble WNLA l vector (h_vec dimension = H_VEC_FULL) ----
        std::vector<crypto_scalar_t> l_vec(H_VEC_FULL, Crypto::ZERO);
        // Blinding part (indices 0..8)
        l_vec[0] = tau_inv * rs[0] - delta * ro[0] + tau * rl[0] - tau2 * rr[0] + tau3 * rv[0];
        for (size_t i = 1; i < 9; ++i)
        {
            l_vec[i] = tau_inv * rs[i] - delta * ro[i] + tau * rl[i] - tau2 * rr[i];
        }
        // Constraint part: per-value blocks at indices 9+idx*17 through 9+idx*17+16
        for (size_t i = 0; i < NV_TOTAL; ++i)
        {
            l_vec[9 + i] = tau_inv * ls[i] + tau * ll_[i] + tau3 * v_1[i];
        }

        // ---- Assemble WNLA n vector (g_vec dimension = G_VEC_FULL) ----
        std::vector<crypto_scalar_t> n_vec(G_VEC_FULL);
        for (size_t i = 0; i < NM_TOTAL; ++i)
        {
            n_vec[i] = c_nR[i] * tau - c_nL[i] * tau2
                       + tau_inv * ns[i] + tau * nl[i] - tau2 * nr[i];
        }

        // ---- Assemble WNLA c vector (same dimension as l = H_VEC_FULL) ----
        std::vector<crypto_scalar_t> c_vec(H_VEC_FULL, Crypto::ZERO);
        // cr_tau (indices 0..8)
        c_vec[0] = Crypto::ONE;
        c_vec[1] = tau_inv * beta;
        c_vec[2] = tau * beta;
        c_vec[3] = tau2 * beta;
        c_vec[4] = tau3 * beta;
        c_vec[5] = tau * tau3 * beta;
        c_vec[6] = tau2 * tau3 * beta;
        c_vec[7] = tau3 * tau3 * beta;
        c_vec[8] = tau3 * tau3 * tau * beta;
        // cl_tau (per-value blocks)
        for (size_t i = 0; i < NV_TOTAL; ++i)
        {
            c_vec[9 + i] = (two * c_lL[i] * tau2 + c_l0[i]).negate();
        }

        // ---- WNLA prove ----
        std::vector<ge_p3> wnla_g(G_VEC_FULL), wnla_h(H_VEC_FULL);
        for (size_t i = 0; i < G_VEC_FULL; ++i) wnla_g[i] = g_p3[i];
        for (size_t i = 0; i < H_VEC_FULL; ++i) wnla_h[i] = h_p3[i];

        std::vector<crypto_point_t> X_points, W_points;

        // Pre-allocate WNLA MSM buffers at max size (round 0)
        const size_t max_x_sz = H_VEC_FULL + G_VEC_FULL;
        const size_t max_w_sz = H_VEC_FULL / 2 + G_VEC_FULL / 2;
        std::vector<crypto_scalar_t> x_scalars(max_x_sz), w_scalars(max_w_sz);
        std::vector<ge_p3> x_points(max_x_sz), w_points(max_w_sz);

        size_t wnla_round = 0;
        while (l_vec.size() + n_vec.size() >= 6)
        {
            const auto &cur_rho = wnla_rho_fwd[wnla_round];
            const auto &rho_inv = wnla_rho_inv[wnla_round];
            const auto &wnla_mu2 = wnla_mu2_vec[wnla_round];

            const auto l_sz = l_vec.size();
            const auto n_sz = n_vec.size();
            const auto half_l = l_sz / 2;
            const auto half_n = n_sz / 2;

            // Compute dot products using direct even/odd indexing (no reduce copies)
            // vx = 2*rho_inv*<n0, n1>_mu2 + <c0, l1> + <c1, l0>
            // vr = <n1, n1>_mu2 + <c1, l1>
            auto vx = Crypto::ZERO;
            auto vr = Crypto::ZERO;
            {
                auto wip_cross = Crypto::ZERO;
                auto wip_odd = Crypto::ZERO;
                auto mu_exp = Crypto::ONE;
                for (size_t i = 0; i < half_n; ++i)
                {
                    mu_exp *= wnla_mu2;
                    wip_cross += n_vec[2 * i] * n_vec[2 * i + 1] * mu_exp;
                    wip_odd += n_vec[2 * i + 1] * n_vec[2 * i + 1] * mu_exp;
                }
                vx = two * rho_inv * wip_cross;
                vr = wip_odd;
            }
            for (size_t i = 0; i < half_l; ++i)
            {
                vx += c_vec[2 * i] * l_vec[2 * i + 1] + c_vec[2 * i + 1] * l_vec[2 * i];
                vr += c_vec[2 * i + 1] * l_vec[2 * i + 1];
            }

            // X = vx*G + <h_even, l_odd> + <h_odd, l_even> + <g_even, rho*n_odd> + <g_odd, rho_inv*n_even>
            crypto_point_t X_pt;
            {
                const size_t total = half_l + half_l + half_n + half_n;
                size_t idx = 0;
                for (size_t i = 0; i < half_l; ++i) { x_scalars[idx] = l_vec[2*i+1] * inv8; x_points[idx] = wnla_h[2*i]; idx++; }
                for (size_t i = 0; i < half_l; ++i) { x_scalars[idx] = l_vec[2*i] * inv8; x_points[idx] = wnla_h[2*i+1]; idx++; }
                for (size_t i = 0; i < half_n; ++i) { x_scalars[idx] = n_vec[2*i+1] * cur_rho * inv8; x_points[idx] = wnla_g[2*i]; idx++; }
                for (size_t i = 0; i < half_n; ++i) { x_scalars[idx] = n_vec[2*i] * rho_inv * inv8; x_points[idx] = wnla_g[2*i+1]; idx++; }
                X_pt = msm_base(x_scalars, x_points, total, vx * inv8);
            }

            // W = vr*G + <h_odd, l_odd> + <g_odd, n_odd>
            crypto_point_t W_pt;
            {
                const size_t total = half_l + half_n;
                size_t idx = 0;
                for (size_t i = 0; i < half_l; ++i) { w_scalars[idx] = l_vec[2*i+1] * inv8; w_points[idx] = wnla_h[2*i+1]; idx++; }
                for (size_t i = 0; i < half_n; ++i) { w_scalars[idx] = n_vec[2*i+1] * inv8; w_points[idx] = wnla_g[2*i+1]; idx++; }
                W_pt = msm_base(w_scalars, w_points, total, vr * inv8);
            }

            X_points.push_back(X_pt);
            W_points.push_back(W_pt);

            // Transcript: derive challenge y
            tr.update(X_pt);
            tr.update(W_pt);
            const auto y = tr.challenge();
            if (!y.valid()) goto try_again;

            // Fold generators: h'[i] = h[2i] + y*h[2i+1], g'[i] = rho*g[2i] + y*g[2i+1]
            // Generator folding requires contiguous even/odd arrays for batch_ss_p3
            std::vector<ge_p3> h_even(half_l), h_odd(half_l), g_even(half_n), g_odd(half_n);
            for (size_t i = 0; i < half_l; ++i) { h_even[i] = wnla_h[2*i]; h_odd[i] = wnla_h[2*i+1]; }
            for (size_t i = 0; i < half_n; ++i) { g_even[i] = wnla_g[2*i]; g_odd[i] = wnla_g[2*i+1]; }

            wnla_h.resize(half_l);
            wnla_g.resize(half_n);
            {
                static const auto ONE_SCALAR = crypto_scalar_t(1);
                ge_double_scalarmult_negate_vartime_batch_ss_p3(
                    wnla_h.data(), ONE_SCALAR.data(), h_even.data(), y.data(), h_odd.data(), half_l);
                ge_double_scalarmult_negate_vartime_batch_ss_p3(
                    wnla_g.data(), cur_rho.data(), g_even.data(), y.data(), g_odd.data(), half_n);
            }

            // Fold scalar vectors in-place
            for (size_t i = 0; i < half_l; ++i)
                c_vec[i] = c_vec[2*i] + y * c_vec[2*i+1];
            c_vec.resize(half_l);

            for (size_t i = 0; i < half_l; ++i)
                l_vec[i] = l_vec[2*i] + y * l_vec[2*i+1];
            l_vec.resize(half_l);

            for (size_t i = 0; i < half_n; ++i)
                n_vec[i] = rho_inv * n_vec[2*i] + y * n_vec[2*i+1];
            n_vec.resize(half_n);

            ++wnla_round;
        }

        // Return only the first M commitments (not padded ones)
        std::vector<crypto_pedersen_commitment_t> result_commitments(M);
        for (size_t j = 0; j < M; ++j)
            result_commitments[j] = V_all[j];

        return {
            crypto_bulletproof_pp_t(C_l, C_r, C_o, C_s, R, X_points, W_points, l_vec, n_vec),
            result_commitments
        };
    }

    // ========================================================================
    // VERIFY (batch)
    // ========================================================================
    bool verify(
        const std::vector<crypto_bulletproof_pp_t> &proofs,
        const std::vector<std::vector<crypto_pedersen_commitment_t>> &commitments,
        size_t N)
    {
        if (N == 0 || N > 64)
        {
            throw std::range_error("N must be between 1 and 64");
        }

        if (proofs.size() != commitments.size())
        {
            return false;
        }

        // Determine max generator sizes across all proofs
        size_t max_G = 0, max_H = 0;
        for (const auto &proof : proofs)
        {
            if (!proof.check_construction())
                return false;
            const auto nr = proof.X.size();
            const size_t g_full = size_t(1) << nr;
            const size_t h_full = size_t(1) << (nr + 1);
            if (g_full > max_G) max_G = g_full;
            if (h_full > max_H) max_H = h_full;
        }

        if (max_G == 0) return false;

        const auto [g_vec, h_vec] = generate_exponents(max_G, max_H);
        const auto two = crypto_scalar_t(2);
        const auto eight = Crypto::EIGHT;

        // Accumulators for single final MSM check
        auto G_scalar = Crypto::ZERO;
        std::vector<crypto_scalar_t> h_gen_scalars(max_H, Crypto::ZERO);
        std::vector<crypto_scalar_t> g_gen_scalars(max_G, Crypto::ZERO);
        crypto_scalar_vector_t batch_scalars;
        crypto_point_vector_t batch_points;

        for (size_t ii = 0; ii < proofs.size(); ++ii)
        {
            const auto &proof = proofs[ii];
            const auto num_rounds = proof.X.size();

            // Infer dimensions from proof structure
            const size_t G_VEC_FULL = size_t(1) << num_rounds;
            const size_t H_VEC_FULL = size_t(1) << (num_rounds + 1);
            const size_t M_pad = G_VEC_FULL / DIM_ND;
            const size_t ND_TOTAL = M_pad * DIM_ND;
            const size_t NM_TOTAL = ND_TOTAL;
            const size_t NV_TOTAL = M_pad * 17;

            const auto M = commitments[ii].size();
            if (M == 0 || M > M_pad) return false;

            // Pad commitments to M_pad with identity point
            std::vector<crypto_point_t> V_all(M_pad, Crypto::Z);
            for (size_t j = 0; j < M; ++j) V_all[j] = commitments[ii][j];

            const auto weight = crypto_scalar_t::random();
            const auto w8 = weight * eight;

            // ---- Reconstruct transcript ----
            scalar_transcript_t tr(BULLETPROOFS_PP_DOMAIN_0);
            for (size_t j = 0; j < M_pad; ++j)
                tr.update(V_all[j]);

            const auto e = tr.challenge();
            if (!e.valid()) return false;

            tr.update(proof.C_l);
            tr.update(proof.C_r);
            tr.update(proof.C_o);
            for (size_t j = 0; j < M_pad; ++j)
                tr.update(V_all[j]);

            const auto rho = tr.challenge();
            if (!rho.valid()) return false;
            const auto lambda = tr.challenge();
            if (!lambda.valid()) return false;
            const auto beta = tr.challenge();
            if (!beta.valid()) return false;
            const auto delta = tr.challenge();
            if (!delta.valid()) return false;

            const auto mu = rho * rho;

            // ---- Lambda powers for M_pad values ----
            const size_t lambda_len = M_pad * 17 + 1;
            std::vector<crypto_scalar_t> lambda_vec(lambda_len);
            {
                auto lp = Crypto::ONE;
                for (size_t i = 0; i < lambda_len; ++i) { lambda_vec[i] = lp; lp *= lambda; }
            }

            std::vector<crypto_scalar_t> lcc(M_pad), lambda_sum_vec(M_pad);
            for (size_t idx = 0; idx < M_pad; ++idx)
            {
                lcc[idx] = lambda_vec[17 * idx];
                auto ls_acc = Crypto::ZERO;
                for (size_t k = 1; k <= DIM_ND; ++k)
                    ls_acc += lambda_vec[idx * 17 + k];
                lambda_sum_vec[idx] = ls_acc;
            }

            std::vector<crypto_scalar_t> mu_vec(NM_TOTAL);
            {
                auto mp = Crypto::ONE;
                for (size_t i = 0; i < NM_TOTAL; ++i) { mp *= mu; mu_vec[i] = mp; }
            }
            // c_l0[idx*17+j] = lambda^(idx*17+j+1) for j=0..15, 0 for j=16
            std::vector<crypto_scalar_t> c_l0(NV_TOTAL, Crypto::ZERO);
            for (size_t idx = 0; idx < M_pad; ++idx)
                for (size_t j = 0; j < DIM_ND; ++j)
                    c_l0[idx * 17 + j] = lambda_vec[idx * 17 + j + 1];

            // ---- C_s transcript, get tau ----
            tr.update(proof.C_s);
            const auto tau = tr.challenge();
            if (!tau.valid()) return false;

            // Batch invert mu, tau, and e+j values
            std::vector<crypto_scalar_t> mu_inv_pow(NM_TOTAL);
            crypto_scalar_t tau_inv;
            std::vector<crypto_scalar_t> c_lL(NV_TOTAL, Crypto::ZERO);
            {
                std::vector<crypto_scalar_t> to_invert;
                to_invert.reserve(2 + DIM_NP);
                to_invert.push_back(mu);
                to_invert.push_back(tau);
                for (size_t j = 0; j < DIM_NP; ++j)
                    to_invert.push_back(e + crypto_scalar_t(j));
                const auto inv_batch = crypto_scalar_vector_t(std::move(to_invert)).invert();

                const auto mu_inv = inv_batch[0];
                auto mip = Crypto::ONE;
                for (size_t i = 0; i < NM_TOTAL; ++i) { mip *= mu_inv; mu_inv_pow[i] = mip; }

                tau_inv = inv_batch[1];

                for (size_t idx = 0; idx < M_pad; ++idx)
                {
                    const auto neg_ls = lambda_sum_vec[idx].negate();
                    for (size_t j = 0; j < DIM_NP; ++j)
                        c_lL[idx * 17 + j] = neg_ls * inv_batch[2 + j];
                }
            }
            const auto tau2 = tau * tau;
            const auto tau3 = tau2 * tau;

            // ---- Constraint vectors ----
            std::vector<crypto_scalar_t> c_nL(NM_TOTAL), c_nR(NM_TOTAL);
            {
                const auto base = crypto_scalar_t(DIM_NP);
                for (size_t idx = 0; idx < M_pad; ++idx)
                {
                    auto base_pow = Crypto::ONE;
                    for (size_t d = 0; d < DIM_ND; ++d)
                    {
                        const size_t gi = idx * DIM_ND + d;
                        c_nL[gi] = (lcc[idx] * base_pow).negate() * mu_inv_pow[gi];
                        base_pow *= base;
                    }
                }
            }
            for (size_t idx = 0; idx < M_pad; ++idx)
                for (size_t d = 0; d < DIM_ND; ++d)
                {
                    const size_t gi = idx * DIM_ND + d;
                    c_nR[gi] = (lambda_sum_vec[idx] - lambda_vec[idx * 17 + d + 1]) * mu_inv_pow[gi] + e;
                }

            // ---- pn_tau, ps_tau ----
            std::vector<crypto_scalar_t> pn_tau(NM_TOTAL);
            for (size_t i = 0; i < NM_TOTAL; ++i)
                pn_tau[i] = c_nR[i] * tau - c_nL[i] * tau2;

            auto mu_sum = Crypto::ZERO;
            for (size_t i = 0; i < NM_TOTAL; ++i) mu_sum += mu_vec[i];

            const auto ps_tau = weight_inner_product(pn_tau, pn_tau, mu)
                                - two * tau3 * mu_sum;

            // ---- Build WNLA c vector ----
            std::vector<crypto_scalar_t> c_vec(H_VEC_FULL, Crypto::ZERO);
            c_vec[0] = Crypto::ONE;
            c_vec[1] = tau_inv * beta;
            c_vec[2] = tau * beta;
            c_vec[3] = tau2 * beta;
            c_vec[4] = tau3 * beta;
            c_vec[5] = tau * tau3 * beta;
            c_vec[6] = tau2 * tau3 * beta;
            c_vec[7] = tau3 * tau3 * beta;
            c_vec[8] = tau3 * tau3 * tau * beta;

            for (size_t i = 0; i < NV_TOTAL; ++i)
                c_vec[9 + i] = (two * c_lL[i] * tau2 + c_l0[i]).negate();

            // ---- WNLA challenge replay ----
            std::vector<crypto_scalar_t> wnla_challenges(num_rounds);
            for (size_t r = 0; r < num_rounds; ++r)
            {
                tr.update(proof.X[r]);
                tr.update(proof.W[r]);
                const auto y = tr.challenge();
                if (!y.valid()) return false;
                wnla_challenges[r] = y;
            }

            // ---- Track final mu through rounds ----
            const auto &l_final = proof.l;
            const auto &n_final = proof.n;

            auto verify_mu = mu;
            for (size_t r = 0; r < num_rounds; ++r)
                verify_mu = verify_mu * verify_mu;

            // Fold c vector through all rounds (in-place)
            auto c_folded = c_vec;
            for (size_t r = 0; r < num_rounds; ++r)
            {
                const auto &y = wnla_challenges[r];
                const auto half = c_folded.size() / 2;
                for (size_t i = 0; i < half; ++i)
                    c_folded[i] = c_folded[2 * i] + y * c_folded[2 * i + 1];
                c_folded.resize(half);
            }

            const auto v_wnla = weight_inner_product(n_final, n_final, verify_mu)
                                + dot(c_folded, l_final);

            // ---- Generator scalar products via binary expansion ----
            const auto h_sz = H_VEC_FULL;
            const auto g_sz = G_VEC_FULL;

            std::vector<crypto_scalar_t> h_products(h_sz, Crypto::ONE);
            std::vector<crypto_scalar_t> g_products(g_sz, Crypto::ONE);
            {
                auto rr = rho;
                auto rm = mu;
                for (size_t r = 0; r < num_rounds; ++r)
                {
                    const auto &y = wnla_challenges[r];
                    for (size_t i = 0; i < h_sz; ++i)
                    {
                        if ((i >> r) & 1)
                            h_products[i] = h_products[i] * y;
                    }
                    for (size_t i = 0; i < g_sz; ++i)
                    {
                        if ((i >> r) & 1)
                            g_products[i] = g_products[i] * y;
                        else
                            g_products[i] = g_products[i] * rr;
                    }
                    rr = rm;
                    rm = rm * rm;
                }
            }

            const auto final_l_sz = l_final.size();
            const auto final_n_sz = n_final.size();

            // ---- Batch check equation ----
            G_scalar += weight * v_wnla;

            std::vector<crypto_scalar_t> w_l(final_l_sz), w_n(final_n_sz);
            for (size_t j = 0; j < final_l_sz; ++j) w_l[j] = weight * l_final[j];
            for (size_t j = 0; j < final_n_sz; ++j) w_n[j] = weight * n_final[j];

            std::vector<crypto_scalar_t> w_pn(NM_TOTAL);
            for (size_t i = 0; i < NM_TOTAL; ++i) w_pn[i] = weight * pn_tau[i];

            // +<h_folded, l_final>
            for (size_t i = 0; i < h_sz; ++i)
            {
                const auto j = i >> num_rounds;
                if (j < final_l_sz)
                    h_gen_scalars[i] += h_products[i] * w_l[j];
            }

            // +<g_folded, n_final>
            for (size_t i = 0; i < g_sz; ++i)
            {
                const auto j = i >> num_rounds;
                if (j < final_n_sz)
                    g_gen_scalars[i] += g_products[i] * w_n[j];
            }

            G_scalar -= weight * ps_tau;

            // -<g_vec, pn_tau>
            for (size_t i = 0; i < NM_TOTAL; ++i)
                g_gen_scalars[i] -= w_pn[i];

            // Pre-compute repeated scalar products
            const auto neg_tau_inv_w8 = w8 * tau_inv.negate();
            const auto delta_w8 = w8 * delta;
            const auto neg_tau_w8 = w8 * tau.negate();
            const auto tau2_w8 = w8 * tau2;
            const auto neg_2tau3_w8 = w8 * (two * tau3).negate();
            const auto neg_2tau3_w = weight * (two * tau3).negate();

            batch_scalars.append(neg_tau_inv_w8);
            batch_points.append(proof.C_s);

            batch_scalars.append(delta_w8);
            batch_points.append(proof.C_o);

            batch_scalars.append(neg_tau_w8);
            batch_points.append(proof.C_l);

            batch_scalars.append(tau2_w8);
            batch_points.append(proof.C_r);

            batch_scalars.append(neg_2tau3_w8);      // -2*tau^3 * R
            batch_points.append(proof.R);

            // -2*tau^3 * sum_j(lcc[j] * V_j) for all M_pad values
            for (size_t j = 0; j < M_pad; ++j)
            {
                batch_scalars.append(neg_2tau3_w * lcc[j]);
                batch_points.append(V_all[j]);
            }

            // WNLA round adjustments
            for (size_t r = 0; r < num_rounds; ++r)
            {
                const auto &y = wnla_challenges[r];
                batch_scalars.append(w8 * y.negate());
                batch_points.append(proof.X[r]);

                batch_scalars.append(w8 * (Crypto::ONE - y * y));
                batch_points.append(proof.W[r]);
            }
        }

        // Add accumulated generator terms to the batch
        batch_scalars.append(G_scalar);
        batch_points.append(Crypto::G);

        for (size_t i = 0; i < max_H; ++i)
        {
            batch_scalars.append(h_gen_scalars[i]);
            batch_points.append(h_vec[i]);
        }

        for (size_t i = 0; i < max_G; ++i)
        {
            batch_scalars.append(g_gen_scalars[i]);
            batch_points.append(g_vec[i]);
        }

        // Final MSM: if all proofs are valid, the linear combination equals the identity point
        return batch_scalars.inner_product(batch_points).empty();
    }

    bool verify(
        const crypto_bulletproof_pp_t &proof,
        const std::vector<crypto_pedersen_commitment_t> &commitments,
        size_t N)
    {
        return verify(
            std::vector<crypto_bulletproof_pp_t>(1, proof),
            std::vector<std::vector<crypto_pedersen_commitment_t>>(1, commitments),
            N);
    }
} // namespace Crypto::RangeProofs::BulletproofsPP
