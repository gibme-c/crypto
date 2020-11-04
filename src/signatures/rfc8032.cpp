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

#include <crypto_constants.h>
#include <cryptopp/sha.h>
#include <helpers/scalar_transcript_t.h>
#include <signatures/rfc8032.h>

/**
 * This method allows us to load a scalar value that is less than 256-bits and
 * is generally only used when attempting to reduce a 512-bit hash into a normal
 * scalar value
 * @param input
 * @param start
 * @param end
 * @return
 */
static inline crypto_scalar_t load_partial_scalar(const CryptoPP::byte input[64], size_t start, size_t end)
{
    std::vector<unsigned char> temp(input + start, input + end);

    temp.resize(32);

    return crypto_scalar_t(temp);
}

/**
 * This method reduces a 512-bit hash into a 256-bit scalar value that we can
 * use with other cryptographic operations
 * @param input
 * @return
 */
static inline crypto_scalar_t reduce_wide_hash(const CryptoPP::byte input[64])
{
    const auto a = load_partial_scalar(input, 0, 21);

    const auto b = load_partial_scalar(input, 21, 42);

    const auto c = load_partial_scalar(input, 42, 64);

    return a + (b * Crypto::TWO.pow(168)) + (c * Crypto::TWO.pow(336));
}

namespace Crypto::RFC8032
{
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

        /**
         * We need to compute a 512-bit SHA512 digest using the alpha point, the public key
         * of the private key used to sign, and the message itself
         */
        CryptoPP::byte hramDigest[64];

        {
            auto hash_context = new CryptoPP::SHA512();

            hash_context->Update(signature.LR.L.data(), signature.LR.L.size());

            hash_context->Update(public_key.data(), public_key.size());

            hash_context->Update(static_cast<const CryptoPP::byte *>(message), message_length);

            hash_context->Final(hramDigest);

            free(hash_context);
        }

        // We then reduce the 512-bit SHA512 digest into a scalar value
        const auto k = reduce_wide_hash(hramDigest);

        // [R + (k * A)] mod l
        const auto challenge = alpha_point + (k * public_key);

        // l * G = [R + (k * A)] mod l
        return challenge == signature.LR.R * G;
    }

    crypto_signature_t generate_signature(const void *message, size_t message_length, const crypto_scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(secret_key)

        const auto public_key = secret_key * G;

        const auto message_digest = crypto_hash_t::sha512(message, message_length);

    try_again:
        // helps to compute a deterministic scalar value using some entropy
        scalar_transcript_t alpha_transcript(message_digest, public_key, crypto_scalar_t::random());

        const auto alpha_scalar = alpha_transcript.challenge();

        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        const auto alpha_point = alpha_scalar.point();

        /**
         * We need to compute a 512-bit SHA512 digest using the alpha point, the public key
         * of the private key used to sign, and the message itself
         */
        CryptoPP::byte hramDigest[64];

        {
            auto hash_context = new CryptoPP::SHA512();

            hash_context->Update(alpha_point.data(), alpha_point.size());

            hash_context->Update(public_key.data(), public_key.size());

            hash_context->Update(static_cast<const CryptoPP::byte *>(message), message_length);

            hash_context->Final(hramDigest);

            free(hash_context);
        }

        // We then reduce the 512-bit SHA512 digest into a scalar value
        const auto k = reduce_wide_hash(hramDigest);

        crypto_signature_t signature;

        /**
         * The left-most 256-bits of the signature are the alpha point; however,
         * to reuse the existing signature type, we have to force it into
         * a non-reduced scalar
         */
        signature.LR.L = crypto_scalar_t(alpha_point.serialize());

        /**
         * Compute the right-mode 256-bits of the signature using the alpha_scalar,
         * the reduced digest, and our secret key
         */
        signature.LR.R = alpha_scalar + (k * secret_key);

        return signature;
    }
} // namespace Crypto::RFC8032
