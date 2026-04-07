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
 * @file vrf.cpp
 * @brief ED25519-VRF: native (SHA-3) and RFC 9381 (SHA-512) implementations.
 */

#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <helpers/hd_keys.h>
#include <helpers/scalar_transcript_t.h>
#include <vrf/vrf.h>
#include <tinysha.h>

namespace Crypto::VRF
{
    /**
     * Hash-to-curve for VRF: deterministically maps (public_key, alpha) to a curve point.
     */
    static point_t hash_to_curve(const public_key_t &public_key, const std::vector<unsigned char> &alpha)
    {
        // Domain-separated hash: SHA3(VRF_DOMAIN_0 || PK || alpha) -> point via Elligator + mul8
        Serialization::serializer_t writer;
        writer.pod(VRF_DOMAIN_0);
        writer.pod(public_key);
        writer.bytes(alpha);
        return hash_t::sha3(writer.data(), writer.size()).point();
    }

    /**
     * Compute VRF output beta from Gamma: beta = SHA3(cofactor * Gamma)
     */
    static hash_t gamma_to_output(const point_t &gamma)
    {
        // Cofactor clearing ensures uniqueness of the output
        const auto cofactored = Crypto::EIGHT * gamma;
        return hash_t::sha3(cofactored);
    }

    std::tuple<vrf_proof_t, hash_t> prove(const scalar_t &secret_key, const std::vector<unsigned char> &alpha)
    {
        SCALAR_NZ_OR_THROW(secret_key);

        const auto public_key = secret_key * Crypto::G;

        // Hash input to curve
        const auto h_point = hash_to_curve(public_key, alpha);

        // VRF output point: Gamma = sk * H
        const auto gamma = secret_key * h_point;

    try_again:
        // Nonce via scalar transcript (domain-separated, entropy-mixed)
        scalar_transcript_t k_transcript(VRF_DOMAIN_0, secret_key, h_point, scalar_t::random());

        auto k = k_transcript.challenge();

        if (!k.valid())
        {
            goto try_again;
        }

        // Commitments: U = kG, V = kH
        const auto u_commit = k * Crypto::G;
        const auto v_commit = k * h_point;

        // Challenge: c = H(domain, PK, H, Gamma, U, V)
        scalar_transcript_t challenge_transcript(VRF_DOMAIN_0);
        challenge_transcript.update(public_key, h_point);
        challenge_transcript.update(gamma);
        challenge_transcript.update(u_commit, v_commit);

        const auto c = challenge_transcript.challenge();

        if (!c.valid())
        {
            goto try_again;
        }

        // Response: s = k + c * sk
        const auto s = k + (c * secret_key);

        const auto beta = gamma_to_output(gamma);

        return {{gamma, c, s}, beta};
    }

    std::tuple<bool, hash_t>
        verify(const public_key_t &public_key, const std::vector<unsigned char> &alpha, const vrf_proof_t &proof)
    {
        const hash_t empty_hash;

        if (!proof.c.valid() || !proof.s.valid())
        {
            return {false, empty_hash};
        }

        if (!proof.gamma.check_subgroup() || !public_key.check_subgroup())
        {
            return {false, empty_hash};
        }

        // Recompute hash-to-curve
        const auto h_point = hash_to_curve(public_key, alpha);

        // Reconstruct commitments: U' = sG - cPK, V' = sH - c*Gamma
        const auto neg_c = scalar_t() - proof.c;
        const auto u_prime = (proof.s * Crypto::G) + (neg_c * public_key);
        const auto v_prime = (proof.s * h_point) + (neg_c * proof.gamma);

        // Recompute challenge
        scalar_transcript_t challenge_transcript(VRF_DOMAIN_0);
        challenge_transcript.update(public_key, h_point);
        challenge_transcript.update(proof.gamma);
        challenge_transcript.update(u_prime, v_prime);

        const auto c_prime = challenge_transcript.challenge();

        if (!c_prime.valid())
        {
            return {false, empty_hash};
        }

        if ((c_prime - proof.c).is_nonzero())
        {
            return {false, empty_hash};
        }

        const auto beta = gamma_to_output(proof.gamma);

        return {true, beta};
    }
} // namespace Crypto::VRF

// RFC 9381: ECVRF-EDWARDS25519-SHA512-ELL2 (suite_string = 0x04)
namespace Crypto::VRF::RFC9381
{
    static constexpr unsigned char SUITE_STRING = 0x04;

    /**
     * Hash-to-curve per RFC 9381 Section 5.4.1.2:
     * SHA-512(suite || 0x01 || PK || alpha) -> first 32 bytes -> Elligator2 -> mul8
     */
    static point_t hash_to_curve(const public_key_t &public_key, const std::vector<unsigned char> &alpha)
    {
        unsigned char digest[64];

        {
            // suite || 0x01 || PK || alpha = 1 + 1 + 32 + alpha.size()
            std::vector<unsigned char> buf;
            buf.reserve(34 + alpha.size());
            buf.push_back(SUITE_STRING);
            buf.push_back(0x01);
            buf.insert(buf.end(), public_key.data(), public_key.data() + 32);
            buf.insert(buf.end(), alpha.begin(), alpha.end());

            tinysha_sha512(buf.data(), buf.size(), digest, 64);
        }

        // Take first 32 bytes, apply Elligator2, then cofactor clearing
        ge_p2 point2 = {};
        ge_p1p1 point1p1 = {};
        ge_p3 point3 = {};

        ge_fromfe_frombytes_vartime(&point2, digest);
        ge_mul8(&point1p1, &point2);
        ge_p1p1_to_p3(&point3, &point1p1);

        return point_t(point3);
    }

    /**
     * 16-byte truncated challenge per RFC 9381 Section 5.4.3:
     * c_bytes = SHA-512(suite || 0x02 || H || Gamma || U || V || 0x00)[0..16]
     */
    static std::array<unsigned char, 16> generate_challenge(
        const point_t &h_point,
        const point_t &gamma,
        const point_t &u_commit,
        const point_t &v_commit)
    {
        unsigned char digest[64];

        {
            // suite || 0x02 || H || Gamma || U || V || 0x00 = 1+1+32+32+32+32+1 = 131 bytes
            unsigned char buf[131];
            buf[0] = SUITE_STRING;
            buf[1] = 0x02;
            std::memcpy(buf + 2, h_point.data(), 32);
            std::memcpy(buf + 34, gamma.data(), 32);
            std::memcpy(buf + 66, u_commit.data(), 32);
            std::memcpy(buf + 98, v_commit.data(), 32);
            buf[130] = 0x00;

            tinysha_sha512(buf, sizeof(buf), digest, 64);
        }

        std::array<unsigned char, 16> c_bytes = {};

        std::copy(digest, digest + 16, c_bytes.begin());

        return c_bytes;
    }

    /**
     * Convert 16-byte truncated challenge to a scalar (little-endian, zero-padded to 32 bytes).
     */
    static scalar_t challenge_to_scalar(const std::array<unsigned char, 16> &c_bytes)
    {
        std::vector<unsigned char> padded(32, 0);

        std::copy(c_bytes.begin(), c_bytes.end(), padded.begin());

        return scalar_t(padded);
    }

    /**
     * VRF output per RFC 9381 Section 5.2:
     * beta = SHA-512(suite || 0x03 || cofactor*Gamma || 0x00), truncated to 32 bytes
     */
    static hash_t gamma_to_output(const point_t &gamma)
    {
        const auto cofactored = Crypto::EIGHT * gamma;

        unsigned char digest[64];

        {
            // suite || 0x03 || cofactored || 0x00 = 1+1+32+1 = 35 bytes
            unsigned char buf[35];
            buf[0] = SUITE_STRING;
            buf[1] = 0x03;
            std::memcpy(buf + 2, cofactored.data(), 32);
            buf[34] = 0x00;

            tinysha_sha512(buf, sizeof(buf), digest, 64);
        }

        return hash_t(std::vector<unsigned char>(digest, digest + 32));
    }

    std::tuple<vrf_rfc9381_proof_t, hash_t> prove(const scalar_t &secret_key, const std::vector<unsigned char> &alpha)
    {
        SCALAR_NZ_OR_THROW(secret_key);

        const auto public_key = secret_key * Crypto::G;

        // Hash input to curve (SHA-512 + Elligator2 + mul8)
        const auto h_point = hash_to_curve(public_key, alpha);

        // VRF output point: Gamma = sk * H
        const auto gamma = secret_key * h_point;

        // Deterministic nonce via HMAC-SHA512 (RFC 9381 Section 5.4.2.2)
        // k = HMAC-SHA512(key=secret_key_bytes, data=H_bytes) reduced mod l
        const auto h_bytes = h_point.serialize();

        const auto k_hmac = calculate_hmac_sha512(secret_key.data(), 32, h_bytes.data(), h_bytes.size());

        // Reduce 64-byte HMAC output to scalar mod l
        unsigned char k_bytes[64];

        std::copy(k_hmac.begin(), k_hmac.end(), k_bytes);

        sc_reduce(k_bytes, 64);

        const auto k = scalar_t(std::vector<unsigned char>(k_bytes, k_bytes + 32));

        if (!k.valid())
        {
            throw std::runtime_error("VRF RFC9381: nonce reduction produced zero scalar");
        }

        // Commitments: U = kG, V = kH
        const auto u_commit = k * Crypto::G;
        const auto v_commit = k * h_point;

        // 16-byte truncated challenge
        const auto c_bytes = generate_challenge(h_point, gamma, u_commit, v_commit);

        const auto c = challenge_to_scalar(c_bytes);

        // Response: s = k - c * sk (mod l) — note: RFC 9381 uses subtraction
        const auto s = k - (c * secret_key);

        const auto beta = gamma_to_output(gamma);

        return {{gamma, c_bytes, s}, beta};
    }

    std::tuple<bool, hash_t> verify(
        const public_key_t &public_key,
        const std::vector<unsigned char> &alpha,
        const vrf_rfc9381_proof_t &proof)
    {
        const hash_t empty_hash;

        if (!proof.s.valid() || !proof.gamma.check_subgroup() || !public_key.check_subgroup())
        {
            return {false, empty_hash};
        }

        const auto c = challenge_to_scalar(proof.c);

        // Recompute hash-to-curve
        const auto h_point = hash_to_curve(public_key, alpha);

        // Reconstruct commitments: U' = sG + cPK, V' = sH + c*Gamma
        // (RFC 9381 uses s = k - c*sk, so U' = sG + cPK = kG = U)
        const auto u_prime = (proof.s * Crypto::G) + (c * public_key);
        const auto v_prime = (proof.s * h_point) + (c * proof.gamma);

        // Recompute 16-byte challenge
        const auto c_prime = generate_challenge(h_point, proof.gamma, u_prime, v_prime);

        // Compare challenges (constant-time via std::equal on fixed-size arrays)
        if (proof.c != c_prime)
        {
            return {false, empty_hash};
        }

        const auto beta = gamma_to_output(proof.gamma);

        return {true, beta};
    }
} // namespace Crypto::VRF::RFC9381
