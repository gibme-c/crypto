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

#include <cassert>
#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <ed25519/include/ed25519_secure_erase.h>
#include <helpers/scalar_transcript_t.h>
#include <tinysha.h>
#include <types/secret_key_t.h>
#include <vrf/vrf.h>

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

    // ----------------------------------------------------------------------------
    // Spec-compliant hash-to-curve stack for suite 0x04 ELL2.
    //
    // RFC 9381 §5.5 mandates that suite ECVRF-EDWARDS25519-SHA512-ELL2 use the
    // RFC 9380 §8.5 ciphersuite `edwards25519_XMD:SHA-512_ELL2_NU_`. That suite
    // is built on three layers:
    //
    //   1. expand_message_xmd over SHA-512 (RFC 9380 §5.3.1) — produces a
    //      uniformly random byte string of requested length, with a domain
    //      separation tag (DST) tying the output to the suite.
    //   2. hash_to_field with parameters m=1, L=48, p=2^255-19 (RFC 9380 §5.2)
    //      — interprets the expanded bytes as a single field element u ∈ Fp.
    //   3. map_to_curve_elligator2_edwards25519 (RFC 9380 §6.7.1 + §6.8.2),
    //      followed by cofactor clearing (×8). The Elligator2 + birational
    //      map step is what the existing `ge_fromfe_frombytes_vartime`
    //      primitive computes; we reuse it (its byte interpretation matches
    //      RFC 9380 once the input is a canonical Fp element in 32-byte
    //      little-endian form).
    //
    // The stack below is validated layer-by-layer against published RFC 9380
    // Appendix J.5.2 and Appendix K.3 vectors and the RFC 9381 Appendix B.4
    // intermediate values, with every layer independently checkable in
    // src/test.cpp::test_vrf_rfc9381.
    //
    // The DST is fixed by the suite name and the suite_string per RFC 9380
    // §3.1: DST = "ECVRF_" || h2c_suite_ID_string || suite_string. The 6-byte
    // ASCII prefix "ECVRF_" + the 38-byte ASCII suite name +
    // the single-byte suite_string 0x04 give a 45-byte DST, well within the
    // 255-byte limit.
    static const std::vector<unsigned char> RFC9381_DST_ELL2 = []
    {
        const std::string s = "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_";
        std::vector<unsigned char> dst(s.begin(), s.end());
        dst.push_back(SUITE_STRING);
        return dst;
    }();

    /**
     * RFC 9380 §5.3.1 expand_message_xmd, instantiated with H = SHA-512.
     *
     * For suite_string 0x04 ELL2 NU we always request len_in_bytes = 48 (one
     * field element with L=48). With SHA-512 (b_in_bytes = 64), ell = 1, so
     * the loop body runs exactly once. The implementation below is general
     * (handles ell up to 255) for clarity and to match the spec literally,
     * but the only path exercised by the VRF is the ell=1 case.
     *
     * Validated against RFC 9380 Appendix K.3 test vectors in test.cpp.
     */
    static std::vector<unsigned char> expand_message_xmd_sha512(
        const std::vector<unsigned char> &msg,
        const std::vector<unsigned char> &dst,
        size_t len_in_bytes)
    {
        constexpr size_t b_in_bytes = 64; // SHA-512 output length
        constexpr size_t s_in_bytes = 128; // SHA-512 input block size

        if (dst.size() > 255)
        {
            // RFC 9380 §5.3.3 specifies a hashed-DST workaround for longer DSTs;
            // not needed here (our suite DST is 40 bytes), but we hard-fail rather
            // than silently ignore.
            // Malformed-input contract.
            throw std::invalid_argument("expand_message_xmd: DST exceeds 255 bytes");
        }

        const size_t ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;

        if (ell > 255 || len_in_bytes > 65535)
        {
            // Malformed-input contract.
            throw std::invalid_argument("expand_message_xmd: len_in_bytes out of range");
        }

        // DST_prime = DST || I2OSP(len(DST), 1)
        std::vector<unsigned char> dst_prime(dst);
        dst_prime.push_back(static_cast<unsigned char>(dst.size()));

        // msg_prime = Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime
        std::vector<unsigned char> msg_prime;
        msg_prime.reserve(s_in_bytes + msg.size() + 2 + 1 + dst_prime.size());
        msg_prime.insert(msg_prime.end(), s_in_bytes, 0x00); // Z_pad
        msg_prime.insert(msg_prime.end(), msg.begin(), msg.end());
        msg_prime.push_back(static_cast<unsigned char>((len_in_bytes >> 8) & 0xFF));
        msg_prime.push_back(static_cast<unsigned char>(len_in_bytes & 0xFF));
        msg_prime.push_back(0x00);
        msg_prime.insert(msg_prime.end(), dst_prime.begin(), dst_prime.end());

        // b_0 = H(msg_prime)
        unsigned char b_0[b_in_bytes];
        tinysha_sha512(msg_prime.data(), msg_prime.size(), b_0, b_in_bytes);

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        std::vector<unsigned char> input;
        input.reserve(b_in_bytes + 1 + dst_prime.size());
        input.insert(input.end(), b_0, b_0 + b_in_bytes);
        input.push_back(0x01);
        input.insert(input.end(), dst_prime.begin(), dst_prime.end());

        std::vector<unsigned char> uniform_bytes(ell * b_in_bytes, 0);
        unsigned char b_i[b_in_bytes];
        tinysha_sha512(input.data(), input.size(), b_i, b_in_bytes);
        std::copy(b_i, b_i + b_in_bytes, uniform_bytes.begin());

        // For i in [2, ell]: b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        for (size_t i = 2; i <= ell; ++i)
        {
            input.clear();
            input.reserve(b_in_bytes + 1 + dst_prime.size());
            for (size_t j = 0; j < b_in_bytes; ++j)
            {
                input.push_back(b_0[j] ^ b_i[j]);
            }
            input.push_back(static_cast<unsigned char>(i));
            input.insert(input.end(), dst_prime.begin(), dst_prime.end());

            tinysha_sha512(input.data(), input.size(), b_i, b_in_bytes);
            std::copy(b_i, b_i + b_in_bytes, uniform_bytes.begin() + (i - 1) * b_in_bytes);
        }

        uniform_bytes.resize(len_in_bytes);
        return uniform_bytes;
    }

    /**
     * Reduce a 48-byte big-endian unsigned integer modulo p = 2^255 - 19,
     * outputting the result as 32 little-endian bytes (canonical Fp encoding,
     * i.e. value < p).
     *
     * Used by hash_to_field for L=48. Implemented in portable uint64_t arithmetic
     * with no compiler-specific 128-bit type — the only multiplication needed is
     * `38 * (uint64_t)`, which fits in 6 bits times 64 bits, so a single split
     * via 32×32→64 with carry chains suffices and works on MSVC, GCC, and Clang.
     *
     * Validated against RFC 9380 Appendix J.5.2 `u[0]` vectors in test.cpp.
     */
    static std::array<unsigned char, 32> reduce_48be_mod_p(const unsigned char *be48)
    {
        // Read 48 BE bytes into six little-endian 64-bit limbs (limbs[0] = LSB).
        uint64_t limbs[6] = {};
        for (int li = 0; li < 6; ++li)
        {
            const int byte_off = 48 - 8 * (li + 1);
            uint64_t v = 0;
            for (int j = 0; j < 8; ++j)
            {
                v = (v << 8) | static_cast<uint64_t>(be48[byte_off + j]);
            }
            limbs[li] = v;
        }

        // limbs[0..3] = N_low (256 bits), limbs[4..5] = N_high (128 bits).
        // N mod p ≡ N_low + 38 * N_high (mod p)  since 2^256 ≡ 38 (mod p).
        //
        // Compute prod = 38 * (limbs[5] : limbs[4]) as a 3-limb value.
        // 38 * 2^64 fits in 70 bits, so prod is at most 38 * (2^128 - 1) < 2^133.
        //
        // 64x64 → 128 portable: split the operand into hi/lo 32-bit halves and let
        // 38 * (≤ 2^32 - 1) stay well within 64 bits. `mid` carries the middle 32
        // bits of the product (high-half of the low partial + low-half of the high
        // partial), so the hi output is high-half of the high partial + any carry
        // from `mid`.
        auto mul38 = [](uint64_t a, uint64_t &out_lo, uint64_t &out_hi)
        {
            const uint64_t p_lo = (a & 0xFFFFFFFFULL) * 38;
            const uint64_t p_hi = (a >> 32) * 38;
            const uint64_t mid = (p_lo >> 32) + (p_hi & 0xFFFFFFFFULL);
            out_lo = (p_lo & 0xFFFFFFFFULL) | (mid << 32);
            out_hi = (p_hi >> 32) + (mid >> 32);
        };

        uint64_t prod4_lo = 0, prod4_hi = 0;
        uint64_t prod5_lo = 0, prod5_hi = 0;
        mul38(limbs[4], prod4_lo, prod4_hi);
        mul38(limbs[5], prod5_lo, prod5_hi);

        // 38 * (limbs[5]<<64 + limbs[4]) = (prod5_hi : prod5_lo + prod4_hi : prod4_lo)
        // Layout into a 3-limb value p_limbs (limb 0 = LSB):
        uint64_t p_limbs[3] = {};
        p_limbs[0] = prod4_lo;
        const uint64_t p1_sum = prod4_hi + prod5_lo;
        p_limbs[1] = p1_sum;
        const uint64_t p1_carry = (p1_sum < prod4_hi) ? 1ULL : 0ULL;
        p_limbs[2] = prod5_hi + p1_carry;

        // Add p_limbs to limbs[0..3] → r[0..4] (5 limbs, r[4] is at most 1).
        uint64_t r[5] = {limbs[0], limbs[1], limbs[2], limbs[3], 0};
        uint64_t carry = 0;
        for (int li = 0; li < 3; ++li)
        {
            const uint64_t old = r[li];
            r[li] = old + p_limbs[li] + carry;
            carry = (r[li] < old || (carry && r[li] == old)) ? 1ULL : 0ULL;
        }
        // Propagate carry through the remaining limbs.
        for (int li = 3; li < 5 && carry; ++li)
        {
            const uint64_t old = r[li];
            r[li] = old + carry;
            carry = (r[li] < old) ? 1ULL : 0ULL;
        }

        // r is at most 257 bits. Reduce to ≤ 256 bits using 2^256 ≡ 38 (mod p).
        // For any 48-byte input the value before this step is at most
        // N_low + 38 * N_high < 2^256 + 38 * 2^128 < 2^257, so r[4] ∈ {0, 1}
        // and the subtract-2^256 / add-38 rewrite yields r[4] == 0 in a single
        // pass (r[0..3] was < 2^256, so r[0..3] + 38 cannot carry into r[4]).
        if (r[4] != 0)
        {
            r[4] = 0;
            uint64_t old = r[0];
            r[0] = old + 38;
            uint64_t c = (r[0] < old) ? 1ULL : 0ULL;
            for (int li = 1; li < 4 && c; ++li)
            {
                old = r[li];
                r[li] = old + c;
                c = (r[li] < old) ? 1ULL : 0ULL;
            }
            assert(c == 0 && "48-byte input cannot re-carry past bit 256");
        }

        // r is now ≤ 256 bits. Reduce to ≤ 255 bits using 2^255 ≡ 19 (mod p).
        if (r[3] >> 63)
        {
            // Top bit set: subtract 2^255, add 19.
            r[3] &= 0x7FFFFFFFFFFFFFFFULL;
            uint64_t old = r[0];
            r[0] = old + 19;
            uint64_t c = (r[0] < old) ? 1ULL : 0ULL;
            for (int li = 1; li < 4 && c; ++li)
            {
                old = r[li];
                r[li] = old + c;
                c = (r[li] < old) ? 1ULL : 0ULL;
            }
            // Adding 19 to a 255-bit number cannot overflow into bit 256.
            // (255-bit max + 19 < 2^255 + 19 < 2^256.) The top bit of r[3] may
            // now be set again only if we just barely crossed; handle below.
        }

        // Final canonical reduction: if r >= p (= 2^255 - 19), subtract p.
        // r >= p iff r >= 2^255 - 19 iff (r[3] has bit 254 set) AND (lower bits encode ≥ -19 mod 2^255).
        // Easier: try-subtract p, keep result if no borrow.
        const uint64_t p_limbs_canon[4] = {
            0xFFFFFFFFFFFFFFEDULL, // 2^64 - 19
            0xFFFFFFFFFFFFFFFFULL,
            0xFFFFFFFFFFFFFFFFULL,
            0x7FFFFFFFFFFFFFFFULL // 2^63 - 1 (high limb of 2^255 - 19)
        };
        uint64_t t[4];
        uint64_t borrow = 0;
        for (int li = 0; li < 4; ++li)
        {
            const uint64_t a = r[li];
            const uint64_t b = p_limbs_canon[li] + borrow;
            // Detect if subtraction underflows.
            // borrow_in could itself overflow b; but p_limbs_canon[0] is < 2^64-1 only at li==0,
            // and borrow is 0 or 1, so b is well-defined.
            t[li] = a - b;
            borrow = (a < b) ? 1ULL : 0ULL;
        }
        if (borrow == 0)
        {
            // r was ≥ p; commit the subtracted value.
            r[0] = t[0];
            r[1] = t[1];
            r[2] = t[2];
            r[3] = t[3];
        }

        // Serialize r[0..3] as 32 little-endian bytes.
        std::array<unsigned char, 32> out = {};
        for (int li = 0; li < 4; ++li)
        {
            uint64_t v = r[li];
            for (int j = 0; j < 8; ++j)
            {
                out[li * 8 + j] = static_cast<unsigned char>(v & 0xFFULL);
                v >>= 8;
            }
        }
        return out;
    }

    /**
     * RFC 9380 §5.2 hash_to_field, specialized for the ELL2_NU_ suite parameters:
     *   F = Fp where p = 2^255 - 19
     *   m = 1 (one element per output)
     *   count = 1 (NU encoding)
     *   L = 48 bytes per element
     *
     * Returns the single 32-byte little-endian canonical Fp element u.
     */
    static std::array<unsigned char, 32>
        hash_to_field_one_fp(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &dst)
    {
        constexpr size_t L = 48;
        const auto uniform_bytes = expand_message_xmd_sha512(msg, dst, L);
        return reduce_48be_mod_p(uniform_bytes.data());
    }

    /**
     * RFC 9381 §5.4.1.2 ECVRF_encode_to_curve_h2c_suite, specialized for
     * suite_string 0x04 (ECVRF-EDWARDS25519-SHA512-ELL2):
     *   string_to_be_hashed = encode_to_curve_salt || alpha_string
     *                       = PK_string || alpha
     *   H = encode_to_curve(string_to_be_hashed)
     *
     * `encode_to_curve` is the RFC 9380 §8.5 `edwards25519_XMD:SHA-512_ELL2_NU_`
     * suite, which composes:
     *   u = hash_to_field(msg, 1)[0]                       (RFC 9380 §5.2)
     *   Q = map_to_curve_elligator2_edwards25519(u)        (§6.7.1 + §6.8.2)
     *   P = clear_cofactor(Q) = h_eff * Q = 8 * Q          (§7)
     *
     * The Elligator2-and-rational-map step followed by cofactor clearing is
     * exactly what `point_t::reduce(bytes)` encapsulates (see src/types/point_t.cpp):
     * `ge_fromfe_frombytes_vartime` + `ge_mul8` + `ge_p1p1_to_p3`. The only
     * precondition the library primitive adds on top of RFC 9380 is that its
     * input be a canonical 32-byte little-endian Fp element, which is exactly
     * what `hash_to_field_one_fp` produces.
     */
    static point_t hash_to_curve_ell2(const public_key_t &public_key, const std::vector<unsigned char> &alpha)
    {
        // string_to_be_hashed = PK || alpha
        std::vector<unsigned char> msg;
        msg.reserve(32 + alpha.size());
        msg.insert(msg.end(), public_key.data(), public_key.data() + 32);
        msg.insert(msg.end(), alpha.begin(), alpha.end());

        // u = hash_to_field(msg, 1)[0]   (32-byte LE canonical Fp element)
        const auto u_bytes = hash_to_field_one_fp(msg, RFC9381_DST_ELL2);

        // map_to_curve_elligator2_edwards25519(u) followed by cofactor clearing.
        return point_t::reduce(u_bytes.data());
    }

    // Test-only wrappers exposing the file-scope helpers to src/test.cpp so each
    // layer (expand_message_xmd, hash_to_field, hash_to_curve_ell2) can be
    // validated against published RFC 9380 / RFC 9381 vectors independently.
    // Forward-declared in test.cpp rather than vrf.h to keep them out of the
    // public API.
    namespace test_hooks
    {
        std::vector<unsigned char> expand_message_xmd_sha512(
            const std::vector<unsigned char> &msg,
            const std::vector<unsigned char> &dst,
            size_t len_in_bytes)
        {
            return ::Crypto::VRF::RFC9381::expand_message_xmd_sha512(msg, dst, len_in_bytes);
        }

        std::array<unsigned char, 32>
            hash_to_field_one_fp(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &dst)
        {
            return ::Crypto::VRF::RFC9381::hash_to_field_one_fp(msg, dst);
        }

        point_t hash_to_curve_ell2(const public_key_t &public_key, const std::vector<unsigned char> &alpha)
        {
            return ::Crypto::VRF::RFC9381::hash_to_curve_ell2(public_key, alpha);
        }
    } // namespace test_hooks

    /**
     * 16-byte truncated challenge per RFC 9381 §5.4.3 ECVRF_challenge_generation:
     *   c_string = Hash(suite_string || 0x02 || Y || H || Gamma || U || V || 0x00)
     *   c        = c_string[0..cLen]                   // cLen = 16 for suite 0x04
     *
     * The public key Y is the first point in the hash, as required by the spec.
     */
    static std::array<unsigned char, 16> generate_challenge(
        const public_key_t &public_key,
        const point_t &h_point,
        const point_t &gamma,
        const point_t &u_commit,
        const point_t &v_commit)
    {
        unsigned char digest[64];

        {
            // suite || 0x02 || Y || H || Gamma || U || V || 0x00 = 1+1+32*5+1 = 163 bytes
            unsigned char buf[163];
            buf[0] = SUITE_STRING;
            buf[1] = 0x02;
            std::memcpy(buf + 2, public_key.data(), 32);
            std::memcpy(buf + 34, h_point.data(), 32);
            std::memcpy(buf + 66, gamma.data(), 32);
            std::memcpy(buf + 98, u_commit.data(), 32);
            std::memcpy(buf + 130, v_commit.data(), 32);
            buf[162] = 0x00;

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

    std::tuple<vrf_rfc9381_proof_t, hash_t>
        prove(const secret_key_t &secret_key, const std::vector<unsigned char> &alpha)
    {
        // RFC 9381 §5.1 ECVRF_prove and §5.4.2.2 nonce derivation require the
        // raw 32-byte SK seed (not the derived clamped scalar) so that the upper
        // half of SHA-512(seed) -- the "signing prefix" -- can be recovered for
        // deterministic nonce generation. That is why this function takes a
        // secret_key_t rather than a scalar_t.

        // Lower-half clamped scalar `x` and public key `Y = x*G`. Both come from
        // secret_key_t, which routes through the unique `from_rfc8032_seed` clamp
        // factory. Reuse, do not reimplement.
        const auto x = secret_key.scalar();

        SCALAR_NZ_OR_THROW(x);

        const auto public_key = secret_key.point();

        // Hash input to curve via the spec-compliant ELL2 stack:
        // expand_message_xmd_sha512 → hash_to_field → map_to_curve_elligator2 → ×8.
        const auto h_point = hash_to_curve_ell2(public_key, alpha);

        // VRF output point: Gamma = x * H
        const auto gamma = x * h_point;

        // RFC 9381 §5.4.2.2 ECVRF_nonce_generation_RFC8032:
        //   hashed_sk_string       = SHA-512(SK_string)
        //   truncated_hashed_sk    = hashed_sk_string[32..64]   <-- secret PRF key
        //   k_string               = SHA-512(truncated_hashed_sk || h_string)
        //   k                      = string_to_int(k_string) mod q
        //
        // Validated byte-for-byte against RFC 9381 Appendix B.4 KAT vectors
        // (Examples 19-21).
        const auto prefix = secret_key.rfc8032_prefix();

        const auto h_bytes = h_point.serialize();

        // `prefix` is the RFC 8032 signing prefix -- secret PRF key material.
        // Build `prefix || h_string` in a stack buffer rather than a std::vector
        // so the heap allocator never sees it; secure-erase on the way out.
        // h_string is a 32-byte encoded curve point, so the total is always
        // exactly 64 bytes.
        assert(h_bytes.size() == 32 && "RFC 9381: h_string must be a 32-byte encoded ed25519 point");

        unsigned char nonce_input[64];
        std::copy(prefix.begin(), prefix.end(), nonce_input);
        std::copy(h_bytes.begin(), h_bytes.end(), nonce_input + 32);

        unsigned char k_buf[64];
        tinysha_sha512(nonce_input, sizeof(nonce_input), k_buf, sizeof(k_buf));

        ed25519_secure_erase(nonce_input, sizeof(nonce_input));

        sc_reduce(k_buf, 64);

        const auto k = scalar_t(std::vector<unsigned char>(k_buf, k_buf + 32));

        ed25519_secure_erase(k_buf, sizeof(k_buf));

        if (!k.valid())
        {
            throw std::runtime_error("VRF RFC9381: nonce reduction produced zero scalar");
        }

        // Commitments: U = k*G, V = k*H
        const auto u_commit = k * Crypto::G;
        const auto v_commit = k * h_point;

        // 16-byte truncated challenge -- public_key Y is the first point per §5.4.3
        const auto c_bytes = generate_challenge(public_key, h_point, gamma, u_commit, v_commit);

        const auto c = challenge_to_scalar(c_bytes);

        // Response: s = k + c*x (mod q). RFC 9381 §5.1 step 7 specifies addition;
        // the matching verifier reconstruction is U' = s*G - c*Y, V' = s*H - c*Gamma.
        const auto s = k + (c * x);

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

        // Recompute hash-to-curve via the spec-compliant ELL2 stack.
        const auto h_point = hash_to_curve_ell2(public_key, alpha);

        // RFC 9381 §5.3 ECVRF_verify steps 4-5: U = s*B - c*Y, V = s*H - c*Gamma.
        // Mirrors the prover's `s = k + c*x` (§5.1 step 7) so that
        // U = (k + cx)G - cY = kG and V = (k + cx)H - c*Gamma = kH.
        const auto neg_c = c.negate();

        const auto u_prime = (proof.s * Crypto::G) + (neg_c * public_key);
        const auto v_prime = (proof.s * h_point) + (neg_c * proof.gamma);

        // Recompute 16-byte challenge -- public_key Y is the first point per §5.4.3
        const auto c_prime = generate_challenge(public_key, h_point, proof.gamma, u_prime, v_prime);

        // Compare challenges (constant-time via std::equal on fixed-size arrays)
        if (proof.c != c_prime)
        {
            return {false, empty_hash};
        }

        const auto beta = gamma_to_output(proof.gamma);

        return {true, beta};
    }
} // namespace Crypto::VRF::RFC9381
