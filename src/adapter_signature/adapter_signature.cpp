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

#include <adapter_signature/adapter_signature.h>
#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <dleq/dleq.h>
#include <helpers/scalar_transcript_t.h>

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
        scalar_transcript_t r_transcript(ADAPTER_DOMAIN_0, public_key, message_digest, scalar_t::random(), secret_key);

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

    adapted_signature_t adapt(const adapter_signature_t &pre_signature, const scalar_t &witness_y)
    {
        SCALAR_NZ_OR_THROW(witness_y);

        // Adapted Schnorr signature under the adapter Fiat-Shamir domain: (R', s)
        //   R' = pre_signature.adapted_nonce  (lifted unchanged from the pre-sig)
        //   s  = s' + y                       (pre-sig response + witness)
        // Verification equation: s*G == R' + c*PK where c = H(ADAPTER_DOMAIN_0, R', PK, msg).
        return adapted_signature_t {pre_signature.adapted_nonce, pre_signature.s_prime + witness_y};
    }

    bool check_adapted_signature(
        const hash_t &message_digest,
        const public_key_t &public_key,
        const adapted_signature_t &signature)
    {
        if (!signature.s.valid())
        {
            return false;
        }

        if (!public_key.check_subgroup() || !signature.R_prime.check_subgroup())
        {
            return false;
        }

        // Recompute the challenge: c = H(adapter_domain, R', PK, message)
        scalar_transcript_t challenge_transcript(ADAPTER_DOMAIN_0, signature.R_prime, public_key, message_digest);

        const auto challenge = challenge_transcript.challenge();

        if (!challenge.valid())
        {
            return false;
        }

        // Verify: s * G == R' + c * PK
        const auto lhs = signature.s * Crypto::G;
        const auto rhs = signature.R_prime + (challenge * public_key);

        return lhs == rhs;
    }

    scalar_t extract(
        const adapter_signature_t &pre_signature,
        const adapted_signature_t &signature,
        const point_t &statement_Y)
    {
        // y = s - s' (the witness is the difference between adapted and pre-signature responses)
        const auto y = signature.s - pre_signature.s_prime;

        // Verify extracted witness: y*G should equal Y
        const auto check = y * Crypto::G;

        if (!(check == statement_Y))
        {
            throw std::invalid_argument("Extracted witness does not match statement point");
        }

        return y;
    }
} // namespace Crypto::AdapterSignature
