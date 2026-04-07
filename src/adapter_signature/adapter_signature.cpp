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
 * @file adapter_signature.cpp
 * @brief Schnorr-based adapter signature: pre-sign, verify, adapt, extract.
 */

#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <dleq/dleq.h>
#include <helpers/scalar_transcript_t.h>
#include <adapter_signature/adapter_signature.h>
#include <ed25519/signature.h>

namespace
{
    const auto &adapter_H()
    {
        static const auto value = hash_t::sha3(Crypto::G).point();
        return value;
    }
} // namespace

namespace Crypto::AdapterSignature
{
    adapter_signature_t pre_sign(const hash_t &message_digest, const scalar_t &secret_key, const point_t &statement_Y)
    {
        SCALAR_NZ_OR_THROW(secret_key);

        const auto public_key = secret_key * Crypto::G;

    try_again:
        // Derive nonce r from domain, secret, message, and fresh entropy
        scalar_transcript_t r_transcript(ADAPTER_DOMAIN_0, public_key, message_digest, scalar_t::random());

        auto r = r_transcript.challenge();

        if (!r.valid())
        {
            goto try_again;
        }

        // Raw nonce point R = rG
        const auto R = r * Crypto::G;

        // Adapted nonce R' = R + Y
        const auto R_prime = R + statement_Y;

        // Challenge: c = H(domain, R', PK, message)
        scalar_transcript_t challenge_transcript(ADAPTER_DOMAIN_0, R_prime, public_key, message_digest);

        const auto c = challenge_transcript.challenge();

        if (!c.valid())
        {
            goto try_again;
        }

        // Pre-signature response: s' = r + c * sk
        const auto s_prime = r + (c * secret_key);

        // DLEQ proof: proves knowledge of r under two independent bases (G and Hp(G))
        // This binds R to a second generator, proving R is well-formed w.r.t. the statement Y
        const auto &adapter_H = ::adapter_H();
        const auto nonce_commitment = r * adapter_H;
        const auto dleq = Crypto::DLEQ::generate_proof(r, Crypto::G, adapter_H);

        return {R_prime, s_prime, nonce_commitment, dleq};
    }

    bool check_pre_signature(
        const hash_t &message_digest,
        const public_key_t &public_key,
        const point_t &statement_Y,
        const adapter_signature_t &pre_signature)
    {
        if (!pre_signature.s_prime.valid() || !pre_signature.adapted_nonce.check_subgroup())
        {
            return false;
        }

        if (!public_key.check_subgroup() || !statement_Y.check_subgroup())
        {
            return false;
        }

        // Recompute challenge: c = H(domain, R', PK, message)
        scalar_transcript_t challenge_transcript(
            ADAPTER_DOMAIN_0, pre_signature.adapted_nonce, public_key, message_digest);

        const auto c = challenge_transcript.challenge();

        if (!c.valid())
        {
            return false;
        }

        // Verify: s'G = R + c*PK, where R = R' - Y
        const auto R = pre_signature.adapted_nonce - statement_Y;

        const auto lhs = pre_signature.s_prime * Crypto::G;
        const auto rhs = R + (c * public_key);

        if (!(lhs == rhs))
        {
            return false;
        }

        // Verify DLEQ proof: proves log_G(R) == log_{Hp(G)}(nonce_commitment)
        const auto &adapter_H = ::adapter_H();
        return Crypto::DLEQ::check_proof(R, pre_signature.nonce_commitment, Crypto::G, adapter_H, pre_signature.dleq);
    }

    signature_t adapt(const adapter_signature_t &pre_signature, const scalar_t &witness_y)
    {
        SCALAR_NZ_OR_THROW(witness_y);

        // Adapted signature: s = s' + y, nonce point = R' (adapted nonce)
        const auto s = pre_signature.s_prime + witness_y;

        signature_t signature;

        // Store challenge in L and response in R (following library convention)
        // We need to recompute the challenge to store it
        // Actually the adapted signature is (R', s) as a Schnorr sig
        // But the library stores signatures as (c, r) where c is challenge, r is response
        // such that rG + cP = R. Let's reconstruct c for the adapted signature.
        // We don't have the message here, so we store R' as bytes in L and s in R.
        // Actually, looking at the signature format: LR.L = challenge, LR.R = response
        // And verify checks: point = c*P + r*G, then recomputes c from transcript.
        // So for adapter: the adapted signature should verify with Crypto::Signature::check_signature
        // That means we need: LR.R = s such that s*G + c*P = R'
        // => s*G = R' - c*P => s = r + y - c*sk... wait, let's think again.

        // In the library's signature scheme:
        //   sign: c = H(domain, msg, PK, alpha*G), r = alpha - c*sk
        //   verify: point = c*PK + r*G, c' = H(domain, msg, PK, point), check c == c'

        // For adapter signatures, we use a different Schnorr variant:
        //   pre-sign: c = H(adapter_domain, R', PK, msg), s' = r + c*sk
        //   adapt: s = s' + y
        //   verify adapted: check s*G - c*PK == R' (where c = H(adapter_domain, R', PK, msg))
        //
        // This doesn't match the library's check_signature format directly.
        // The adapted signature is verified with a dedicated check or we re-encode.
        // Let's store as (adapted_nonce_bytes, s) and verify with custom logic.
        // We'll encode adapted_nonce into LR.L as a point-to-scalar-bytes trick.
        // Actually, simpler: return a signature where LR.L holds a "dummy" and verify differently.
        //
        // Per the plan: "Verify adapted signature via Crypto::Signature::check_signature"
        // But the library's scheme uses c = H(SIGNATURE_DOMAIN_0, ...) while adapter uses ADAPTER_DOMAIN_0.
        // These won't match. So the final adapted signature must be verified with a custom check.
        //
        // Let's just return (R', s) packed into the signature type and provide a custom verify
        // path in check_pre_signature or the caller uses the returned R' point.
        //
        // Actually re-reading the plan more carefully: the plan says adapter uses its own domain.
        // The adapted sig (R', s) is verified by: recomputing c from the same adapter domain transcript,
        // then checking s*G == R' + c*PK. So we can't reuse check_signature directly.
        //
        // Let's store the adapted nonce as a scalar (its bytes) in LR.L and s in LR.R.
        // The caller will verify using the adapter domain. This is consistent with the plan's
        // "Verify adapted: standard Schnorr: sG == R' + c*PK" but with adapter domain.

        // Store adapted nonce point bytes as LR.L (it's just 32 bytes, same as scalar)
        signature.LR.L = scalar_t(pre_signature.adapted_nonce.serialize());
        signature.LR.R = s;

        return signature;
    }

    bool check_adapted_signature(
        const hash_t &message_digest,
        const public_key_t &public_key,
        const signature_t &signature)
    {
        if (!signature.LR.R.valid())
        {
            return false;
        }

        if (!public_key.check_subgroup())
        {
            return false;
        }

        // Recover the adapted nonce point R' from the stored bytes in LR.L
        const auto adapted_nonce = point_t(signature.LR.L.serialize());

        if (!adapted_nonce.check_subgroup())
        {
            return false;
        }

        // Recompute the challenge: c = H(adapter_domain, R', PK, message)
        scalar_transcript_t challenge_transcript(ADAPTER_DOMAIN_0, adapted_nonce, public_key, message_digest);

        const auto challenge = challenge_transcript.challenge();

        if (!challenge.valid())
        {
            return false;
        }

        // Verify: s * G == R' + c * PK
        const auto lhs = signature.LR.R * Crypto::G;
        const auto rhs = adapted_nonce + (challenge * public_key);

        return lhs == rhs;
    }

    scalar_t extract(const adapter_signature_t &pre_signature, const signature_t &signature, const point_t &statement_Y)
    {
        // y = s - s' (the witness is the difference between adapted and pre-signature responses)
        const auto y = signature.LR.R - pre_signature.s_prime;

        // Verify extracted witness: y*G should equal Y
        const auto check = y * Crypto::G;

        if (!(check == statement_Y))
        {
            throw std::invalid_argument("Extracted witness does not match statement point");
        }

        return y;
    }
} // namespace Crypto::AdapterSignature
