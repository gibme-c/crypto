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
// https://github.com/SarangNoether/skunkworks/tree/pybullet

#include <crypto_constants.h>
#include <helpers/scalar_transcript_t.h>
#include <mutex>
#include <proofs/bulletproofs.h>
#include <proofs/ringct.h>

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
static std::tuple<crypto_point_vector_t, crypto_point_vector_t> generate_exponents(size_t count)
{
    std::scoped_lock lock(bulletproofs_mutex);

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

        writer.pod(BULLETPROOFS_DOMAIN_1);

        L_cached.append(crypto_hash_t::sha3(writer).point());

        writer.pod(BULLETPROOFS_DOMAIN_2);

        R_cached.append(crypto_hash_t::sha3(writer).point());
    }

    return {L_cached, R_cached};
}

namespace Crypto::RangeProofs::Bulletproofs
{
    /**
     * Helps to calculate an inner product round
     */
    struct InnerProductRound
    {
        InnerProductRound(
            crypto_point_vector_t G,
            crypto_point_vector_t H,
            const crypto_point_t &U,
            crypto_scalar_vector_t a,
            crypto_scalar_vector_t b,
            scalar_transcript_t tr):
            G(std::move(G)), H(std::move(H)), U(U), a(std::move(a)), b(std::move(b)), tr(std::move(tr))
        {
        }

        /**
         * Computes the inner product for the values provided during the initialization of the structure
         * @return {L, R, a, b}
         */
        std::tuple<std::vector<crypto_point_t>, std::vector<crypto_point_t>, crypto_scalar_t, crypto_scalar_t> compute()
        {
            if (done)
            {
                return {L.container, R.container, a.container[0], b.container[0]};
            }

            auto n = G.size();

            while (n > 1)
            {
                n /= 2;

                const auto a1 = a.slice(0, n), a2 = a.slice(n, a.size());

                const auto b1 = b.slice(0, n), b2 = b.slice(n, b.size());

                const auto G1 = G.slice(0, n), G2 = G.slice(n, G.size());

                const auto H1 = H.slice(0, n), H2 = H.slice(n, H.size());

                const auto cL = a1.inner_product(b2), cR = a2.inner_product(b1);

                L.append(Crypto::INV_EIGHT * (a1.inner_product(G2) + b2.inner_product(H1) + (cL * U)));

                R.append(Crypto::INV_EIGHT * (a2.inner_product(G1) + b1.inner_product(H2) + (cR * U)));

                tr.update(L.back());

                tr.update(R.back());

                const auto x = tr.challenge();

                if (!x.valid())
                {
                    throw std::runtime_error("x cannot be zero");
                }

                G = G1.dbl_mult(x.invert(), G2, x);

                H = H1.dbl_mult(x, H2, x.invert());

                a = (a1 * x) + (a2 * x.invert());

                b = (b1 * x.invert()) + (b2 * x);
            }

            done = true;

            return {L.container, R.container, a.container[0], b.container[0]};
        }

      private:
        bool done = false;
        scalar_transcript_t tr;
        crypto_point_vector_t G, H;
        crypto_point_t U;
        crypto_point_vector_t L, R;
        crypto_scalar_vector_t a, b;
    };

    std::tuple<crypto_bulletproof_t, std::vector<crypto_pedersen_commitment_t>> prove(
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

        crypto_point_vector_t V;

        crypto_scalar_vector_t aL, aR;

        for (size_t i = 0; i < M; ++i)
        {
            V.append(Crypto::RingCT::generate_pedersen_commitment(blinding_factors[i], amounts[i]));

            aL.extend(crypto_scalar_t(amounts[i]).to_bits(N));
        }

        for (const auto &bit : aL.container)
        {
            aR.append(bit - Crypto::ONE);
        }

    retry:
        const auto alpha = crypto_scalar_t::random();

        if (!alpha.valid())
        {
            goto retry;
        }

        scalar_transcript_t tr(BULLETPROOFS_DOMAIN_0);

        tr.update(V.container);

        const auto A = Crypto::INV_EIGHT * (aL.inner_product(Gi) + aR.inner_product(Hi) + (alpha * G));

        crypto_scalar_vector_t sL(crypto_scalar_t::random(MN)), sR(crypto_scalar_t::random(MN));

        const auto rho = crypto_scalar_t::random();

        if (!rho.valid())
        {
            goto retry;
        }

        const auto S = Crypto::INV_EIGHT * (sL.inner_product(Gi) + sR.inner_product(Hi) + (rho * G));

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

        const auto y_powers = crypto_scalar_vector_t(y.pow_expand(MN));

        const auto l0 = aL - crypto_scalar_vector_t(MN, z);

        const auto &l1 = sL;

        crypto_scalar_vector_t zeros_twos;

        auto z_cache = z.squared();

        for (size_t j = 0; j < M; ++j)
        {
            for (size_t i = 0; i < N; ++i)
            {
                zeros_twos.append(z_cache * powers_of_two[i]);
            }

            z_cache *= z;
        }

        auto r0 = aR + crypto_scalar_vector_t(MN, z);

        r0 = r0 * y_powers;

        r0 = r0 + zeros_twos;

        const auto r1 = y_powers * sR;

        const auto t1 = l0.inner_product(r1) + l1.inner_product(r0);

        const auto t2 = l1.inner_product(r1);

        const auto tau1 = crypto_scalar_t::random(), tau2 = crypto_scalar_t::random();

        if (!tau1.valid() || !tau2.valid())
        {
            goto retry;
        }

        const auto T1 = Crypto::INV_EIGHT * t1.dbl_mult(Crypto::H, tau1, Crypto::G);

        const auto T2 = Crypto::INV_EIGHT * t2.dbl_mult(Crypto::H, tau2, Crypto::G);

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

        const auto l = l0 + (l1 * x);

        const auto r = r0 + (r1 * x);

        const auto t = l.inner_product(r);

        tr.update(taux);

        tr.update(mu);

        tr.update(t);

        const auto x_ip = tr.challenge();

        if (!x_ip.valid())
        {
            goto retry;
        }

        crypto_point_vector_t Hi_points(Hi.size());

        for (size_t i = 0; i < Hi.size(); ++i)
        {
            Hi_points[i] = y_inv.pow(i) * Hi[i];
        }

        const auto Hx_ip = x_ip * H;

        // we try here as if we fail the challenge in the inner product round then we need to try again
        try
        {
            const auto [L, R, a, b] = InnerProductRound(Gi, Hi_points, Hx_ip, l, r, tr).compute();

            return {crypto_bulletproof_t(A, S, T1, T2, taux, mu, L, R, a, b, t), V.container};
        }
        catch (const std::exception &e)
        {
            PRINTF(e.what())

            goto retry;
        }
    }

    bool verify(
        const std::vector<crypto_bulletproof_t> &proofs,
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

        auto y0 = Crypto::ZERO, y1 = Crypto::ZERO, z1 = Crypto::ZERO, z3 = Crypto::ZERO;

        std::vector<crypto_scalar_t> Gi_scalars(max_MN, Crypto::ZERO), Hi_scalars(max_MN, Crypto::ZERO);

        crypto_scalar_vector_t scalars;

        crypto_point_vector_t points;

        // loop through all of the proofs in the batch
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

            const auto weight_y = crypto_scalar_t::random(), weight_z = crypto_scalar_t::random();

            scalar_transcript_t tr(BULLETPROOFS_DOMAIN_0);

            tr.update(commitments[ii]);

            tr.update(proof.A);

            tr.update(proof.S);

            const auto y = tr.challenge();

            if (!y.valid())
            {
                return false;
            }

            const auto y_powers = y.pow_expand(MN);

            const auto y_inv_powers = crypto_scalar_vector_t(y_powers).invert().container;

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

            auto k = (z - z.squared()) * crypto_scalar_vector_t(y_powers).sum();

            for (size_t j = 1; j < M + 1; ++j)
            {
                k -= (z_powers[j + 2] * Crypto::TWO.pow_sum(N));
            }

            y1 += (proof.t - k) * weight_y;

            for (size_t j = 0; j < M; ++j)
            {
                scalars.append(z_powers[j + 2] * weight_y);

                points.append(Crypto::EIGHT * commitments[ii][j]);
            }

            scalars.append(x * weight_y);

            points.append(Crypto::EIGHT * proof.T1);

            if (!points.back().valid())
            {
                return false;
            }

            scalars.append(x.squared() * weight_y);

            points.append(Crypto::EIGHT * proof.T2);

            if (!points.back().valid())
            {
                return false;
            }

            scalars.append(weight_z);

            points.append(Crypto::EIGHT * proof.A);

            if (!points.back().valid())
            {
                return false;
            }

            scalars.append(x * weight_z);

            points.append(Crypto::EIGHT * proof.S);

            if (!points.back().valid())
            {
                return false;
            }

            crypto_scalar_vector_t challenges;

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

            for (size_t i = 0; i < MN; ++i)
            {
                auto index = i;

                auto g = proof.g;

                auto h = proof.h * y_inv_powers[i];

                for (size_t j = proof.L.size(); j-- > 0;)
                {
                    const auto J = challenges.size() - j - 1;

                    const auto base_power = size_t(powers_of_two[j].to_uint64_t());

                    if (index / base_power == 0)
                    {
                        g *= challenges_inv[J];

                        h *= challenges[J];
                    }
                    else
                    {
                        g *= challenges[J];

                        h *= challenges_inv[J];

                        index -= base_power;
                    }
                }

                g += z;

                h -= ((z * y_powers[i]) + (z_powers[2 + i / N] * powers_of_two[i % N])) * y_inv_powers[i];

                Gi_scalars[i] += g * weight_z;

                Hi_scalars[i] += h * weight_z;
            }

            z1 += proof.mu * weight_z;

            for (size_t i = 0; i < proof.L.size(); ++i)
            {
                scalars.append(challenges[i].squared() * weight_z);

                points.append(Crypto::EIGHT * proof.L[i]);

                if (!points.back().valid())
                {
                    return false;
                }

                scalars.append(challenges_inv[i].squared() * weight_z);

                points.append(Crypto::EIGHT * proof.R[i]);

                if (!points.back().valid())
                {
                    return false;
                }
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

        return scalars.inner_product(points).empty();
    }

    bool verify(
        const crypto_bulletproof_t &proof,
        const std::vector<crypto_pedersen_commitment_t> &commitments,
        size_t N)
    {
        return verify(
            std::vector<crypto_bulletproof_t>(1, proof),
            std::vector<std::vector<crypto_pedersen_commitment_t>>(1, commitments),
            N);
    }
} // namespace Crypto::RangeProofs::Bulletproofs
