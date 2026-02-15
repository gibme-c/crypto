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

#include <crypto_constants.h>
#include <cryptopp/sha.h>
#include <helpers/scalar_transcript_t.h>
#include <signatures/rfc8032.h>

// Load a sub-range of a 64-byte buffer into a 32-byte scalar (zero-padded on the right)
static inline crypto_scalar_t load_partial_scalar(const CryptoPP::byte input[64], size_t start, size_t end)
{
    std::vector<unsigned char> temp(input + start, input + end);

    temp.resize(32);

    return crypto_scalar_t(temp);
}

// Reduce a 512-bit SHA-512 digest into a scalar: split into three limbs and
// reconstruct as a + b*2^168 + c*2^336 to avoid bias from naive modular reduction
static inline crypto_scalar_t reduce_wide_hash(const CryptoPP::byte input[64])
{
    const auto a = load_partial_scalar(input, 0, 21);

    const auto b = load_partial_scalar(input, 21, 42);

    const auto c = load_partial_scalar(input, 42, 64);

    return a + (b * Crypto::TWO.pow(168)) + (c * Crypto::TWO.pow(336));
}

namespace Crypto::RFC8032
{
    // ---- Verify: check that s*G == R + H(R||A||M)*A ----

    bool check_signature(
        const void *message,
        size_t message_length,
        const crypto_public_key_t &public_key,
        const crypto_signature_t &signature)
    {
        if (!signature.LR.R.valid())
        {
            return false;
        }

        const auto alpha_point = crypto_point_t(signature.LR.L.serialize());

        if (!alpha_point.valid())
        {
            return false;
        }

        // Compute k = H(R || A || M) as a 512-bit SHA-512 digest, then reduce to scalar
        CryptoPP::byte hramDigest[64];

        {
            CryptoPP::SHA512 hash_context;

            hash_context.Update(signature.LR.L.data(), signature.LR.L.size());

            hash_context.Update(public_key.data(), public_key.size());

            hash_context.Update(static_cast<const CryptoPP::byte *>(message), message_length);

            hash_context.Final(hramDigest);
        }

        const auto k = reduce_wide_hash(hramDigest);

        // Verification equation: s*G == R + k*A
        const auto challenge = alpha_point + (k * public_key);

        return challenge == signature.LR.R * G;
    }

    // ---- Sign: produce (R, s) where s = alpha + H(R||A||M)*a ----

    crypto_signature_t generate_signature(const void *message, size_t message_length, const crypto_scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(secret_key)

        const auto public_key = secret_key * G;

        const auto message_digest = crypto_hash_t::sha512(message, message_length);

    try_again:
        // Derive a nonce scalar by hashing the message digest, public key, and fresh randomness
        scalar_transcript_t alpha_transcript(message_digest, public_key, crypto_scalar_t::random());

        const auto alpha_scalar = alpha_transcript.challenge();

        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        const auto alpha_point = alpha_scalar.point();

        // Compute k = H(R || A || M) as a 512-bit SHA-512 digest, then reduce to scalar
        CryptoPP::byte hramDigest[64];

        {
            CryptoPP::SHA512 hash_context;

            hash_context.Update(alpha_point.data(), alpha_point.size());

            hash_context.Update(public_key.data(), public_key.size());

            hash_context.Update(static_cast<const CryptoPP::byte *>(message), message_length);

            hash_context.Final(hramDigest);
        }

        const auto k = reduce_wide_hash(hramDigest);

        crypto_signature_t signature;

        // L stores the commitment point R (encoded as a scalar to fit the signature type)
        signature.LR.L = crypto_scalar_t(alpha_point.serialize());

        // R stores the response scalar: s = alpha + k*a
        signature.LR.R = alpha_scalar + (k * secret_key);

        return signature;
    }
} // namespace Crypto::RFC8032
