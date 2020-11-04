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
#include <helpers/scalar_transcript_t.h>
#include <signatures/signature.h>

namespace Crypto::Signature
{
    bool check_signature(
        const crypto_hash_t &message_digest,
        const crypto_public_key_t &public_key,
        const crypto_signature_t &signature)
    {
        if (!signature.LR.L.valid() || !signature.LR.R.valid())
        {
            return false;
        }

        // P = [(l * P) + (r * G)] mod l
        const auto point = (signature.LR.L * public_key) + (signature.LR.R * G);

        scalar_transcript_t transcript(SIGNATURE_DOMAIN_0, message_digest, public_key, point);

        const auto challenge = transcript.challenge();

        if (!challenge.valid())
        {
            return false;
        }

        // [(c - sL) mod l] != 0
        return (challenge - signature.LR.L).is_nonzero();
    }

    crypto_signature_t complete_signature(const crypto_scalar_t &signing_scalar, const crypto_signature_t &signature)
    {
        SCALAR_OR_THROW(signing_scalar);

        SCALAR_NZ_OR_THROW(signature.LR.L);

        SCALAR_NZ_OR_THROW(signature.LR.R);

        auto finalized_signature = crypto_signature_t(signature.serialize());

        finalized_signature.LR.R -= (signature.LR.L * signing_scalar);

        return finalized_signature;
    }

    crypto_signature_t generate_signature(const crypto_hash_t &message_digest, const crypto_scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(secret_key);

        // A = (a * G) mod l
        const auto public_key = secret_key * G;

        const auto signature = prepare_signature(message_digest, public_key);

        return complete_signature(secret_key, signature);
    }

    crypto_signature_t prepare_signature(const crypto_hash_t &message_digest, const crypto_public_key_t &public_key)
    {
    try_again:
        // help to provide stronger RNG for the alpha scalar
        scalar_transcript_t alpha_transcript(message_digest, public_key, crypto_scalar_t::random());

        const auto alpha_scalar = alpha_transcript.challenge();

        if (!alpha_scalar.valid())
        {
            goto try_again;
        }

        // P = (a * G) mod l
        const auto point = alpha_scalar * G;

        scalar_transcript_t transcript(SIGNATURE_DOMAIN_0, message_digest, public_key, point);

        crypto_signature_t signature;

        signature.LR.L = transcript.challenge();

        if (!signature.LR.L.valid())
        {
            goto try_again;
        }

        signature.LR.R = alpha_scalar;

        return signature;
    }
} // namespace Crypto::Signature
