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
 * @file signature.h
 * @brief Basic (non-ring) Ed25519 signature generation and verification.
 *
 * Provides a straightforward sign/verify API using Ed25519 with a pre-derived scalar as
 * the secret key. This is the library's "custom" variant -- for strict RFC-8032 compliance
 * (deterministic nonce from the raw seed), see rfc8032.h instead.
 */

#ifndef CRYPTO_SIGNATURE_H
#define CRYPTO_SIGNATURE_H

#include <types/crypto_hash_t.h>
#include <types/crypto_signature_t.h>

namespace Crypto::Signature
{
    /**
     * Verifies that @p signature is a valid Ed25519 signature of @p message_digest
     * under @p public_key.
     *
     * @param message_digest the 32-byte hash of the message that was signed
     * @param public_key the signer's public key
     * @param signature the signature to verify
     * @return true if the signature is valid
     */
    bool check_signature(
        const crypto_hash_t &message_digest,
        const crypto_public_key_t &public_key,
        const crypto_signature_t &signature);

    /**
     * Generates an Ed25519 signature in a single call.
     *
     * The public key is derived internally from @p secret_key, so you only need to provide
     * the secret scalar.
     *
     * @param message_digest the 32-byte hash of the message to sign
     * @param secret_key the signer's secret scalar
     * @return the resulting signature
     */
    crypto_signature_t generate_signature(const crypto_hash_t &message_digest, const crypto_scalar_t &secret_key);
} // namespace Crypto::Signature

#endif // CRYPTO_SIGNATURE_H
