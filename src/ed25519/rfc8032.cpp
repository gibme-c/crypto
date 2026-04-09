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
 * @file rfc8032.cpp
 * @brief RFC-8032 Ed25519 signatures using SHA-512 for nonce derivation and wide-hash reduction.
 */

#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <ed25519/rfc8032.h>
#include <helpers/scalar_transcript_t.h>
#include <helpers/wide_reduction.h>
#include <tinysha.h>

namespace Crypto::RFC8032
{
    // ---- Verify: check that s*G == R + H(R||A||M)*A ----

    bool check_signature(
        const void *message,
        size_t message_length,
        const public_key_t &public_key,
        const signature_t &signature)
    {
        if (!signature.LR.R.valid())
        {
            return false;
        }

        // SECURITY: reject small-subgroup public keys to prevent cofactor-8 forgery
        if (!public_key.check_subgroup())
        {
            return false;
        }

        const auto alpha_point = point_t(signature.LR.L.serialize());

        if (!alpha_point.valid())
        {
            return false;
        }

        // Compute k = H(R || A || M) as a 512-bit SHA-512 digest, then reduce to scalar
        unsigned char hramDigest[64];

        {
            std::vector<unsigned char> buf;
            buf.reserve(32 + 32 + message_length);
            buf.insert(buf.end(), signature.LR.L.data(), signature.LR.L.data() + signature.LR.L.size());
            buf.insert(buf.end(), public_key.data(), public_key.data() + public_key.size());
            buf.insert(
                buf.end(),
                static_cast<const unsigned char *>(message),
                static_cast<const unsigned char *>(message) + message_length);

            tinysha_sha512(buf.data(), buf.size(), hramDigest, 64);
        }

        const auto k = reduce_wide_hash(hramDigest);

        // Verification equation: s*G == R + k*A
        const auto challenge = alpha_point + (k * public_key);

        return challenge == signature.LR.R * G;
    }

    // ---- Sign: produce (R, s) where s = alpha + H(R||A||M)*a ----

    signature_t generate_signature(const void *message, size_t message_length, const scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(secret_key)

        const auto public_key = secret_key * G;

        const auto message_digest = hash_t::sha512(message, message_length);

        // Hedged synthetic-nonce signing: α is derived as a transcript hash over
        // (M_digest, A, rand) rather than RFC 8032 §5.1.6's pure-deterministic
        // (prefix || M). This is the hedged synthetic-nonce pattern endorsed by
        // FIPS 186-5 Appendix A and draft-irtf-cfrg-det-sigs-with-noise. The
        // verification equation s·G == R + H(R||A||M)·A holds for any α, so every
        // spec-compliant Ed25519 verifier accepts the resulting signature. Binding
        // M_digest into the transcript means two different messages always produce
        // different α even under RNG failure; the `rand` stir-in additionally
        // defends against fault-injection attacks. Signatures are therefore not
        // byte-reproducible across calls -- callers needing byte-identical output
        // from a (seed, message) pair must use a different library.
        //
        // The `try_again` retry below handles the cryptographically negligible
        // case where the transcript challenge reduces to zero.

    try_again:
        // Derive a nonce scalar by hashing the message digest, public key, and fresh randomness
        scalar_transcript_t alpha_transcript(message_digest, public_key, scalar_t::random(), secret_key);

        const auto alpha_scalar = alpha_transcript.challenge();

        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        const auto alpha_point = alpha_scalar.point();

        // Compute k = H(R || A || M) as a 512-bit SHA-512 digest, then reduce to scalar
        unsigned char hramDigest[64];

        {
            std::vector<unsigned char> buf;
            buf.reserve(32 + 32 + message_length);
            buf.insert(buf.end(), alpha_point.data(), alpha_point.data() + alpha_point.size());
            buf.insert(buf.end(), public_key.data(), public_key.data() + public_key.size());
            buf.insert(
                buf.end(),
                static_cast<const unsigned char *>(message),
                static_cast<const unsigned char *>(message) + message_length);

            tinysha_sha512(buf.data(), buf.size(), hramDigest, 64);
        }

        const auto k = reduce_wide_hash(hramDigest);

        signature_t signature;

        // L stores the commitment point R (encoded as a scalar to fit the signature type)
        signature.LR.L = scalar_t(alpha_point.serialize());

        // R stores the response scalar: s = alpha + k*a
        signature.LR.R = alpha_scalar + (k * secret_key);

        return signature;
    }
} // namespace Crypto::RFC8032
