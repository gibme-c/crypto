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

#include <crypto_constants.h>
#include <ge_double_scalarmult_negate_vartime_batch_ss_p3.h>
#include <ge_multiscalar_mul_vartime.h>
#include <helpers/scalar_transcript_t.h>
#include <mutex>
#include <proofs/bulletproofspp.h>
#include <proofs/ringct.h>

// ============================================================================
// Constants for u64 reciprocal range proof (base-16, 16 hex digits)
// ============================================================================
static constexpr size_t DIM_ND = 16; // number of hex digits
static constexpr size_t DIM_NP = 16; // base (hex)
static constexpr size_t DIM_NM = 16; // multiplier gates = DIM_ND
static constexpr size_t DIM_NV = 17; // DIM_ND + 1
static constexpr size_t DIM_NL = 17; // = DIM_NV
static constexpr size_t H_VEC_CIRCUIT_SZ = 26; // 9 blinding + 17 witness
static constexpr size_t G_VEC_FULL_SZ = 16;
static constexpr size_t H_VEC_FULL_SZ = 32; // next power of 2 >= 26

// ============================================================================
// Generator caching
// ============================================================================
static std::mutex bpp_mutex;

static std::tuple<crypto_point_vector_t, crypto_point_vector_t> generate_exponents()
{
    std::scoped_lock lock(bpp_mutex);

    static crypto_point_vector_t g_cached, h_cached;

    if (g_cached.size() == G_VEC_FULL_SZ && h_cached.size() == H_VEC_FULL_SZ)
    {
        return {g_cached, h_cached};
    }

    auto writer = Serialization::serializer_t();

    for (size_t i = g_cached.size(); i < G_VEC_FULL_SZ; ++i)
    {
        writer.reset();
        writer.uint64(i);
        writer.pod(BULLETPROOFS_PP_DOMAIN_1);
        g_cached.append(crypto_hash_t::sha3(writer).point());
    }

    for (size_t i = h_cached.size(); i < H_VEC_FULL_SZ; ++i)
    {
        writer.reset();
        writer.uint64(i);
        writer.pod(BULLETPROOFS_PP_DOMAIN_2);
        h_cached.append(crypto_hash_t::sha3(writer).point());
    }

    return {g_cached, h_cached};
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

        // Currently only support single-value proofs (M=1)
        if (amounts.size() != 1)
        {
            throw std::runtime_error("BulletproofsPP currently supports single-value proofs only");
        }

        const auto amount = amounts[0];
        const auto &blinding = blinding_factors[0];

        const auto [g_vec, h_vec] = generate_exponents();

        // Extract ge_p3 arrays for MSM
        std::vector<ge_p3> g_p3(G_VEC_FULL_SZ), h_p3(H_VEC_FULL_SZ);
        for (size_t i = 0; i < G_VEC_FULL_SZ; ++i) g_p3[i] = g_vec[i].p3();
        for (size_t i = 0; i < H_VEC_FULL_SZ; ++i) h_p3[i] = h_vec[i].p3();
        const auto G_p3 = Crypto::G.p3();
        const auto inv8 = Crypto::INV_EIGHT;

        // Generate commitment V = amount*G + blinding*h_vec[0]
        // BP++ uses h_vec[0] as the blinding generator (not the standard H)
        const auto V = crypto_scalar_t(amount) * Crypto::G + blinding * h_vec[0];

    try_again:
        // ---- Transcript: bind V, get challenge e ----
        scalar_transcript_t tr(BULLETPROOFS_PP_DOMAIN_0);
        tr.update(V);

        const auto e = tr.challenge();
        if (!e.valid()) goto try_again;

        // ---- Digit decomposition (base-16) ----
        std::vector<crypto_scalar_t> digits(DIM_ND);
        {
            auto val = amount;
            for (size_t i = 0; i < DIM_ND; ++i)
            {
                digits[i] = crypto_scalar_t(val & 0xFu);
                val >>= 4;
            }
        }

        // ---- Multiplicities: count of each digit value ----
        std::vector<crypto_scalar_t> multiplicities(DIM_NP, Crypto::ZERO);
        {
            auto val = amount;
            for (size_t i = 0; i < DIM_ND; ++i)
            {
                const auto digit = val & 0xFu;
                multiplicities[digit] = multiplicities[digit] + Crypto::ONE;
                val >>= 4;
            }
        }

        // ---- Reciprocals: r[i] = 1/(digits[i] + e) ---- (batch inversion)
        std::vector<crypto_scalar_t> reciprocals(DIM_ND);
        {
            std::vector<crypto_scalar_t> sums(DIM_ND);
            for (size_t i = 0; i < DIM_ND; ++i)
            {
                sums[i] = digits[i] + e;
                if (!sums[i].valid()) goto try_again;
            }
            const auto inv = crypto_scalar_vector_t(std::move(sums)).invert();
            for (size_t i = 0; i < DIM_ND; ++i)
                reciprocals[i] = inv[i];
        }

        // ---- Pole commitment R = r_blind * h[0] + <reciprocals, h[9..25]> ----
        const auto r_blind = crypto_scalar_t::random();
        if (!r_blind.valid()) goto try_again;

        crypto_point_t R;
        {
            std::vector<crypto_scalar_t> r_scalars(DIM_ND + 1);
            std::vector<ge_p3> r_points(DIM_ND + 1);
            r_scalars[0] = r_blind * inv8;
            r_points[0] = h_p3[0];
            for (size_t i = 0; i < DIM_ND; ++i)
            {
                r_scalars[i + 1] = reciprocals[i] * inv8;
                r_points[i + 1] = h_p3[9 + i];
            }
            R = msm(r_scalars, r_points, DIM_ND + 1);
        }

        // ---- Wire witnesses (specialized for reciprocal range proof) ----
        // w_l = digits, w_r = reciprocals, w_o = multiplicities
        // Partition: only LL maps (j -> j for j < 16)
        // no = zeros(16), lo = zeros(17), lr = zeros(17) — all eliminated (zero vectors)
        // ll = [multiplicities[0..16], 0] (17 elements)
        const auto &nl = digits;
        const auto &nr = reciprocals;
        std::vector<crypto_scalar_t> ll_(DIM_NV, Crypto::ZERO);
        for (size_t i = 0; i < DIM_NP; ++i) ll_[i] = multiplicities[i];

        // ---- Random blindings ----
        // ro[9]: [r,r,r,r,0,r,r,r,0]
        // rl[9]: [r,r,r,0,r,r,r,0,0]
        // rr[9]: [r,r,0,r,r,r,0,0,0]
        std::vector<crypto_scalar_t> ro(9, Crypto::ZERO), rl(9, Crypto::ZERO), rr(9, Crypto::ZERO);
        {
            // Generate all random values we need
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
        // C_o = INV_EIGHT * (<h, [ro | lo]> + <g, no>)
        //     = INV_EIGHT * sum(ro[i]*h[i] for non-zero ro)  (since lo=0, no=0)
        crypto_point_t C_o;
        {
            // Only non-zero ro entries: indices 0,1,2,3,5,6,7
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
            // rl has non-zero at 0,1,2,4,5,6; ll has non-zero at 0..15; nl = digits (16)
            // h indices: rl uses h[0..9], ll uses h[9..26], nl uses g[0..16]
            const size_t total = 6 + DIM_NP + DIM_ND; // 6 non-zero rl + 16 ll + 16 nl
            std::vector<crypto_scalar_t> s(total);
            std::vector<ge_p3> p(total);
            size_t idx = 0;
            for (size_t i : {0,1,2,4,5,6})
            {
                s[idx] = rl[i] * inv8;
                p[idx] = h_p3[i];
                idx++;
            }
            for (size_t i = 0; i < DIM_NP; ++i)
            {
                s[idx] = ll_[i] * inv8;
                p[idx] = h_p3[9 + i];
                idx++;
            }
            for (size_t i = 0; i < DIM_ND; ++i)
            {
                s[idx] = nl[i] * inv8;
                p[idx] = g_p3[i];
                idx++;
            }
            C_l = msm(s, p, total);
        }

        // C_r = INV_EIGHT * (<h, [rr | lr]> + <g, nr>)
        //     = INV_EIGHT * (sum(rr[i]*h[i]) + sum(nr[i]*g[i]))  (since lr=0)
        crypto_point_t C_r;
        {
            const size_t total = 5 + DIM_ND; // 5 non-zero rr + 16 nr
            std::vector<crypto_scalar_t> s(total);
            std::vector<ge_p3> p(total);
            size_t idx = 0;
            for (size_t i : {0,1,3,4,5})
            {
                s[idx] = rr[i] * inv8;
                p[idx] = h_p3[i];
                idx++;
            }
            for (size_t i = 0; i < DIM_ND; ++i)
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
        tr.update(V);

        const auto rho = tr.challenge();
        if (!rho.valid()) goto try_again;
        const auto lambda = tr.challenge();
        if (!lambda.valid()) goto try_again;
        const auto beta = tr.challenge();
        if (!beta.valid()) goto try_again;
        const auto delta = tr.challenge();
        if (!delta.valid()) goto try_again;

        const auto mu = rho * rho;

        // ---- Compute lambda_vec ----
        // lambda_vec = [1, lambda, lambda^2, ..., lambda^16] (17 elements)
        std::vector<crypto_scalar_t> lambda_vec(DIM_NL);
        {
            auto lp = Crypto::ONE;
            for (size_t i = 0; i < DIM_NL; ++i)
            {
                lambda_vec[i] = lp;
                lp *= lambda;
            }
        }

        // lambda_sum = sum_{k=1}^{16} lambda^k
        auto lambda_sum = Crypto::ZERO;
        for (size_t k = 1; k <= DIM_ND; ++k) lambda_sum += lambda_vec[k];

        // Batch invert mu and beta (2 inversions → 1 batch)
        const auto batch_inv_2 = crypto_scalar_vector_t(std::vector<crypto_scalar_t>{mu, beta}).invert();
        const auto mu_inv = batch_inv_2[0];
        const auto beta_inv = batch_inv_2[1];

        // mu_inv_pow[j] = mu^-(j+1)
        std::vector<crypto_scalar_t> mu_inv_pow(DIM_NM);
        {
            auto mip = Crypto::ONE;
            for (size_t i = 0; i < DIM_NM; ++i)
            {
                mip *= mu_inv;
                mu_inv_pow[i] = mip;
            }
        }

        // ---- Compute constraint vectors (specialized for reciprocal range proof) ----
        // c_nL[j] = -16^j * mu^-(j+1)
        std::vector<crypto_scalar_t> c_nL(DIM_NM);
        {
            auto base_pow = Crypto::ONE;
            const auto base = crypto_scalar_t(DIM_NP);
            for (size_t j = 0; j < DIM_NM; ++j)
            {
                c_nL[j] = base_pow.negate() * mu_inv_pow[j];
                base_pow *= base;
            }
        }

        // c_nR[j] = (lambda_sum - lambda^(j+1) + e * mu^(j+1)) * mu^-(j+1)
        //         = lambda_sum * mu^-(j+1) - lambda^(j+1) * mu^-(j+1) + e
        std::vector<crypto_scalar_t> c_nR(DIM_NM);
        for (size_t j = 0; j < DIM_NM; ++j)
        {
            c_nR[j] = lambda_sum * mu_inv_pow[j] - lambda_vec[j + 1] * mu_inv_pow[j] + e;
        }

        // c_nO, c_lR, c_lO = zeros (all zero for our partition) — eliminated

        // c_lL[j] = -lambda_sum / (e + j) for j < 16, 0 for j = 16 (batch inversion)
        std::vector<crypto_scalar_t> c_lL(DIM_NV, Crypto::ZERO);
        {
            std::vector<crypto_scalar_t> e_plus(DIM_NP);
            for (size_t j = 0; j < DIM_NP; ++j)
                e_plus[j] = e + crypto_scalar_t(j);
            const auto inv = crypto_scalar_vector_t(std::move(e_plus)).invert();
            const auto neg_lambda_sum = lambda_sum.negate();
            for (size_t j = 0; j < DIM_NP; ++j)
                c_lL[j] = neg_lambda_sum * inv[j];
        }

        // c_l0 = [lambda^1, lambda^2, ..., lambda^16] (16 elements = DIM_NV - 1)
        std::vector<crypto_scalar_t> c_l0(DIM_NV - 1);
        for (size_t j = 0; j < DIM_NV - 1; ++j)
        {
            c_l0[j] = lambda_vec[j + 1];
        }

        // ---- Random shift polynomial blindings ----
        auto ls = crypto_scalar_t::random(DIM_NV);
        auto ns = crypto_scalar_t::random(DIM_NM);

        // ---- Compute v_1, rv (value contributions) ----
        // For k=1, linear_comb_coef = 1
        const auto two = crypto_scalar_t(2);
        std::vector<crypto_scalar_t> v_1(DIM_NV - 1);
        for (size_t i = 0; i < DIM_ND; ++i) v_1[i] = two * reciprocals[i];

        std::vector<crypto_scalar_t> rv(9, Crypto::ZERO);
        rv[0] = two * (blinding + r_blind); // combined blinding with factor 2

        // ---- Polynomial coefficients f[0..7] ----
        // Powers mapped: [-2,-1,0,1,2,_,4,5,6] where _ means f[3] should be zero
        // (indices 0-7 map to powers -2 through 6, skipping power 3)
        std::vector<crypto_scalar_t> f(8, Crypto::ZERO);

        // Loop 1 (ns-based): f[0] = -<ns,ns>_mu, f[2], f[3] weighted parts
        {
            auto mu_pow = Crypto::ONE;
            auto ns_ns = Crypto::ZERO;
            auto ns_nl = Crypto::ZERO, ns_cnR = Crypto::ZERO;
            auto ns_nr = Crypto::ZERO, ns_cnL = Crypto::ZERO;
            for (size_t i = 0; i < DIM_NM; ++i)
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
            f[3] = two * (ns_nr + ns_cnL); // weighted part only, dots added below
        }

        // Loop 2 (nl/nr-based): f[4] = -<nl,nl>_mu - 2<nl,c_nR>_mu
        //                        f[5] = -<nr,nr>_mu - 2<nr,c_nL>_mu
        {
            auto mu_pow = Crypto::ONE;
            auto nl_nl = Crypto::ZERO, nl_cnR = Crypto::ZERO;
            auto nr_nr = Crypto::ZERO, nr_cnL = Crypto::ZERO;
            for (size_t i = 0; i < DIM_NM; ++i)
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

        // Unweighted dot products: f[1], f[3] remainder, f[6]
        {
            auto f1_acc = Crypto::ZERO;
            auto f3_clL_ls = Crypto::ZERO, f3_cl0_ll = Crypto::ZERO;
            auto f6_acc = Crypto::ZERO;
            for (size_t i = 0; i < DIM_NV - 1; ++i)
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
            const size_t total = 9 + DIM_NV + DIM_NM;
            std::vector<crypto_scalar_t> s(total);
            std::vector<ge_p3> p(total);
            for (size_t i = 0; i < 9; ++i)
            {
                s[i] = rs[i] * inv8;
                p[i] = h_p3[i];
            }
            for (size_t i = 0; i < DIM_NV; ++i)
            {
                s[9 + i] = ls[i] * inv8;
                p[9 + i] = h_p3[9 + i];
            }
            for (size_t i = 0; i < DIM_NM; ++i)
            {
                s[9 + DIM_NV + i] = ns[i] * inv8;
                p[9 + DIM_NV + i] = g_p3[i];
            }
            C_s = msm(s, p, total);
        }

        // ---- Transcript: get tau ----
        tr.update(C_s);
        const auto tau = tr.challenge();
        if (!tau.valid()) goto try_again;

        const auto tau2 = tau * tau;
        const auto tau3 = tau2 * tau;
        const auto mu2 = mu * mu;    // mu^2
        const auto mu4 = mu2 * mu2;  // mu^4
        const auto mu8 = mu4 * mu4;  // mu^8
        const auto mu16 = mu8 * mu8; // mu^16

        // Batch invert tau and WNLA rho values (5 inversions → 1 batch)
        // WNLA rho sequence: rho, mu, mu², mu⁴
        const auto batch_inv_5 = crypto_scalar_vector_t(
            std::vector<crypto_scalar_t>{tau, rho, mu, mu2, mu4}).invert();
        const auto tau_inv = batch_inv_5[0];
        const std::vector<crypto_scalar_t> wnla_rho_inv = {
            batch_inv_5[1], batch_inv_5[2], batch_inv_5[3], batch_inv_5[4]
        };

        // ---- Assemble WNLA l vector (h_vec dimension = H_VEC_FULL_SZ = 32) ----
        // l = tau^-1 * [rs|ls] - delta * [ro|0] + tau * [rl|ll] - tau^2 * [rr|0] + tau^3 * [rv|v_1]
        // lo, lr are zero vectors — eliminated from computation
        std::vector<crypto_scalar_t> l_vec(H_VEC_FULL_SZ, Crypto::ZERO);
        // Blinding part (indices 0..8): only rv[0] is non-zero
        l_vec[0] = tau_inv * rs[0] - delta * ro[0] + tau * rl[0] - tau2 * rr[0] + tau3 * rv[0];
        for (size_t i = 1; i < 9; ++i)
        {
            l_vec[i] = tau_inv * rs[i] - delta * ro[i] + tau * rl[i] - tau2 * rr[i];
        }
        // Constraint part (indices 9..25): lo=0, lr=0
        for (size_t i = 0; i < DIM_NV - 1; ++i)
        {
            l_vec[9 + i] = tau_inv * ls[i] + tau * ll_[i] + tau3 * v_1[i];
        }
        // Last constraint slot (index 25): ll_[16]=0, v_1 doesn't extend here
        l_vec[9 + DIM_NV - 1] = tau_inv * ls[DIM_NV - 1];

        // ---- Assemble WNLA n vector (g_vec dimension = G_VEC_FULL_SZ = 16) ----
        // pn_tau = -c_nL * tau^2 + c_nR * tau  (c_nO = 0, eliminated)
        // n = pn_tau + tau^-1 * ns + tau * nl - tau^2 * nr  (no = 0, eliminated)
        std::vector<crypto_scalar_t> n_vec(G_VEC_FULL_SZ);
        for (size_t i = 0; i < DIM_NM; ++i)
        {
            n_vec[i] = c_nR[i] * tau - c_nL[i] * tau2
                       + tau_inv * ns[i] + tau * nl[i] - tau2 * nr[i];
        }

        // ---- Assemble WNLA c vector (same dimension as l = H_VEC_FULL_SZ = 32) ----
        // c = [cr_tau | cl_tau] padded to 32
        // cr_tau[9]: [1, beta/tau, beta*tau, beta*tau^2, beta*tau^3, beta*tau^4, beta*tau^5, beta*tau^6, beta*tau^7]
        // cl_tau[17]: 2*(c_lO*tau^3/delta - c_lL*tau^2 + c_lR*tau) - c_l0
        //   For our case: cl_tau = -2*c_lL*tau^2 - c_l0 (first 16), then 0 for index 16
        std::vector<crypto_scalar_t> c_vec(H_VEC_FULL_SZ, Crypto::ZERO);
        // cr_tau
        c_vec[0] = Crypto::ONE;
        c_vec[1] = tau_inv * beta;
        c_vec[2] = tau * beta;
        c_vec[3] = tau2 * beta;
        c_vec[4] = tau3 * beta;
        c_vec[5] = tau * tau3 * beta;
        c_vec[6] = tau2 * tau3 * beta;
        c_vec[7] = tau3 * tau3 * beta;
        c_vec[8] = tau3 * tau3 * tau * beta;
        // cl_tau (indices 9..26): c_lO=0, c_lR=0, simplified
        for (size_t i = 0; i < DIM_NV - 1; ++i)
        {
            c_vec[9 + i] = (two * c_lL[i] * tau2 + c_l0[i]).negate();
        }
        // c_vec[9 + DIM_NV - 1] = 0 (index 25, the 17th constraint slot)

        // ---- WNLA prove ----
        // WNLA rho sequence: rho, mu, mu², mu⁴ (precomputed inverses above)
        const std::vector<crypto_scalar_t> wnla_rho_fwd = {rho, mu, mu2, mu4};
        // WNLA mu² sequence: mu², mu⁴, mu⁸, mu¹⁶ (wnla_mu starts at mu, squares each round)
        const std::vector<crypto_scalar_t> wnla_mu2_vec = {mu2, mu4, mu8, mu16};

        // Convert g_vec and h_vec to ge_p3 for WNLA
        std::vector<ge_p3> wnla_g(G_VEC_FULL_SZ), wnla_h(H_VEC_FULL_SZ);
        for (size_t i = 0; i < G_VEC_FULL_SZ; ++i) wnla_g[i] = g_p3[i];
        for (size_t i = 0; i < H_VEC_FULL_SZ; ++i) wnla_h[i] = h_p3[i];

        std::vector<crypto_point_t> X_points, W_points;

        // Pre-allocate WNLA MSM buffers at max size (round 0)
        // X: 2*half_l + 2*half_n = 2*16 + 2*8 = 48, W: half_l + half_n = 16 + 8 = 24
        const size_t max_x_sz = H_VEC_FULL_SZ + G_VEC_FULL_SZ;
        const size_t max_w_sz = H_VEC_FULL_SZ / 2 + G_VEC_FULL_SZ / 2;
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

        return {
            crypto_bulletproof_pp_t(C_l, C_r, C_o, C_s, R, X_points, W_points, l_vec, n_vec),
            {V}
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

        const auto [g_vec, h_vec] = generate_exponents();
        const auto two = crypto_scalar_t(2);
        const auto eight = Crypto::EIGHT;

        // Accumulators for single final MSM check
        auto G_scalar = Crypto::ZERO;
        std::vector<crypto_scalar_t> h_gen_scalars(H_VEC_FULL_SZ, Crypto::ZERO);
        std::vector<crypto_scalar_t> g_gen_scalars(G_VEC_FULL_SZ, Crypto::ZERO);
        crypto_scalar_vector_t batch_scalars;
        crypto_point_vector_t batch_points;

        for (size_t ii = 0; ii < proofs.size(); ++ii)
        {
            const auto &proof = proofs[ii];

            if (!proof.check_construction())
                return false;

            if (commitments[ii].size() != 1)
                return false;

            const auto &V = commitments[ii][0];
            const auto num_rounds = proof.X.size();

            const auto weight = crypto_scalar_t::random();
            const auto w8 = weight * eight; // for proof points (stored with INV_EIGHT)

            // ---- Reconstruct transcript ----
            scalar_transcript_t tr(BULLETPROOFS_PP_DOMAIN_0);
            tr.update(V);

            const auto e = tr.challenge();
            if (!e.valid()) return false;

            tr.update(proof.C_l);
            tr.update(proof.C_r);
            tr.update(proof.C_o);
            tr.update(V);

            const auto rho = tr.challenge();
            if (!rho.valid()) return false;
            const auto lambda = tr.challenge();
            if (!lambda.valid()) return false;
            const auto beta = tr.challenge();
            if (!beta.valid()) return false;
            const auto delta = tr.challenge();
            if (!delta.valid()) return false;

            const auto mu = rho * rho;

            // ---- lambda_vec, mu_vec ----
            std::vector<crypto_scalar_t> lambda_vec(DIM_NL);
            {
                auto lp = Crypto::ONE;
                for (size_t i = 0; i < DIM_NL; ++i) { lambda_vec[i] = lp; lp *= lambda; }
            }
            auto lambda_sum = Crypto::ZERO;
            for (size_t k = 1; k <= DIM_ND; ++k) lambda_sum += lambda_vec[k];

            std::vector<crypto_scalar_t> mu_vec(DIM_NM);
            {
                auto mp = Crypto::ONE;
                for (size_t i = 0; i < DIM_NM; ++i) { mp *= mu; mu_vec[i] = mp; }
            }
            std::vector<crypto_scalar_t> c_l0(DIM_NV - 1);
            for (size_t j = 0; j < DIM_NV - 1; ++j) c_l0[j] = lambda_vec[j + 1];

            // ---- C_s transcript, get tau ----
            tr.update(proof.C_s);
            const auto tau = tr.challenge();
            if (!tau.valid()) return false;

            // Batch invert mu, tau, and e+j values (2 + 16 = 18 inversions → 1 batch)
            std::vector<crypto_scalar_t> mu_inv_pow(DIM_NM);
            crypto_scalar_t tau_inv;
            std::vector<crypto_scalar_t> c_lL(DIM_NV, Crypto::ZERO);
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
                for (size_t i = 0; i < DIM_NM; ++i) { mip *= mu_inv; mu_inv_pow[i] = mip; }

                tau_inv = inv_batch[1];

                const auto neg_lambda_sum = lambda_sum.negate();
                for (size_t j = 0; j < DIM_NP; ++j)
                    c_lL[j] = neg_lambda_sum * inv_batch[2 + j];
            }
            const auto tau2 = tau * tau;
            const auto tau3 = tau2 * tau;

            // ---- Constraint vectors (same as prove) ----
            std::vector<crypto_scalar_t> c_nL(DIM_NM), c_nR(DIM_NM);
            {
                auto base_pow = Crypto::ONE;
                const auto base = crypto_scalar_t(DIM_NP);
                for (size_t j = 0; j < DIM_NM; ++j)
                {
                    c_nL[j] = base_pow.negate() * mu_inv_pow[j];
                    base_pow *= base;
                }
            }
            for (size_t j = 0; j < DIM_NM; ++j)
            {
                c_nR[j] = lambda_sum * mu_inv_pow[j] - lambda_vec[j + 1] * mu_inv_pow[j] + e;
            }

            // ---- pn_tau, ps_tau (c_nO = 0, so simplified) ----
            std::vector<crypto_scalar_t> pn_tau(DIM_NM);
            for (size_t i = 0; i < DIM_NM; ++i)
            {
                pn_tau[i] = c_nR[i] * tau - c_nL[i] * tau2;
            }

            auto mu_sum = Crypto::ZERO;
            for (size_t i = 0; i < DIM_NM; ++i) mu_sum += mu_vec[i];

            const auto ps_tau = weight_inner_product(pn_tau, pn_tau, mu)
                                - two * tau3 * mu_sum;

            // ---- Build WNLA c vector ----
            std::vector<crypto_scalar_t> c_vec(H_VEC_FULL_SZ, Crypto::ZERO);
            c_vec[0] = Crypto::ONE;
            c_vec[1] = tau_inv * beta;
            c_vec[2] = tau * beta;
            c_vec[3] = tau2 * beta;
            c_vec[4] = tau3 * beta;
            c_vec[5] = tau * tau3 * beta;
            c_vec[6] = tau2 * tau3 * beta;
            c_vec[7] = tau3 * tau3 * beta;
            c_vec[8] = tau3 * tau3 * tau * beta;

            for (size_t i = 0; i < DIM_NV - 1; ++i)
            {
                // Simplified: c_lO=0, c_lR=0
                c_vec[9 + i] = (two * c_lL[i] * tau2 + c_l0[i]).negate();
            }

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
            // h_products[i] = product_r (y_r if bit_r(i)==1, else 1)
            // g_products[i] = product_r (y_r if bit_r(i)==1, else rho_r)
            // Final index j = i >> num_rounds
            const auto h_sz = H_VEC_FULL_SZ;
            const auto g_sz = G_VEC_FULL_SZ;

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

            // ---- Batch check equation: ----
            // 0 = v_wnla*G + <h_folded, l_final> + <g_folded, n_final>
            //     - ps_tau*G - <g_vec, pn_tau>
            //     - C_s*tau_inv + delta*C_o - tau*C_l + tau^2*C_r
            //     - 2*tau^3*(V + R)
            //     - sum_r(y_r*X_r + (y_r^2-1)*W_r)
            //
            // Generators (G, h_vec, g_vec) are raw: use `weight`
            // Proof points (C_s, C_o, C_l, C_r, R, X, W) stored with INV_EIGHT: use `w8`
            // V is raw (no INV_EIGHT): use `weight`

            // +v_wnla * G
            G_scalar += weight * v_wnla;

            // Pre-fold weight into l_final and n_final
            std::vector<crypto_scalar_t> w_l(final_l_sz), w_n(final_n_sz);
            for (size_t j = 0; j < final_l_sz; ++j) w_l[j] = weight * l_final[j];
            for (size_t j = 0; j < final_n_sz; ++j) w_n[j] = weight * n_final[j];

            // Pre-fold weight into pn_tau
            std::vector<crypto_scalar_t> w_pn(DIM_NM);
            for (size_t i = 0; i < DIM_NM; ++i) w_pn[i] = weight * pn_tau[i];

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

            // -ps_tau * G
            G_scalar -= weight * ps_tau;

            // -<g_vec, pn_tau>
            for (size_t i = 0; i < DIM_NM; ++i)
                g_gen_scalars[i] -= w_pn[i];

            // Pre-compute repeated scalar products for batch equation
            const auto neg_tau_inv_w8 = w8 * tau_inv.negate();
            const auto delta_w8 = w8 * delta;
            const auto neg_tau_w8 = w8 * tau.negate();
            const auto tau2_w8 = w8 * tau2;
            const auto neg_2tau3_w8 = w8 * (two * tau3).negate();
            const auto neg_2tau3_w = weight * (two * tau3).negate();

            // Proof point terms (use w8 for INV_EIGHT-stored points):
            batch_scalars.append(neg_tau_inv_w8);   // -C_s * tau_inv
            batch_points.append(proof.C_s);

            batch_scalars.append(delta_w8);          // +delta * C_o
            batch_points.append(proof.C_o);

            batch_scalars.append(neg_tau_w8);        // -tau * C_l
            batch_points.append(proof.C_l);

            batch_scalars.append(tau2_w8);           // +tau^2 * C_r
            batch_points.append(proof.C_r);

            batch_scalars.append(neg_2tau3_w8);      // -2*tau^3 * R (stored with INV_EIGHT)
            batch_points.append(proof.R);

            batch_scalars.append(neg_2tau3_w);       // -2*tau^3 * V (raw, no INV_EIGHT)
            batch_points.append(V);

            // WNLA round adjustments: -(y_r*X_r + (y_r^2-1)*W_r)
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

        for (size_t i = 0; i < H_VEC_FULL_SZ; ++i)
        {
            batch_scalars.append(h_gen_scalars[i]);
            batch_points.append(h_vec[i]);
        }

        for (size_t i = 0; i < G_VEC_FULL_SZ; ++i)
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
