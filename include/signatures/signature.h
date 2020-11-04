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

#ifndef CRYPTO_SIGNATURE_H
#define CRYPTO_SIGNATURE_H

#include <types/crypto_hash_t.h>
#include <types/crypto_signature_t.h>

namespace Crypto::Signature
{
    /**
     * Checks that the supplied signature was generated with the private key for the given public key
     * @param message_digest
     * @param public_key
     * @param signature
     * @return
     */
    bool check_signature(
        const crypto_hash_t &message_digest,
        const crypto_public_key_t &public_key,
        const crypto_signature_t &signature);

    /**
     * Completes the prepared signature
     * @param signing_scalar
     * @param signature
     * @return
     */
    crypto_signature_t complete_signature(const crypto_scalar_t &signing_scalar, const crypto_signature_t &signature);

    /**
     * Generates a single signature (non-ring) using the secret key provided
     * @param message_digest
     * @param secret_key
     * @return
     */
    crypto_signature_t generate_signature(const crypto_hash_t &message_digest, const crypto_scalar_t &secret_key);

    /**
     * Prepares a single signature (non-ring) using the primitive values provided
     * Must be completed via complete_signature before it will validate
     * @param message_digest
     * @param public_key
     * @return
     */
    crypto_signature_t prepare_signature(const crypto_hash_t &message_digest, const crypto_public_key_t &public_key);
} // namespace Crypto::Signature

#endif // CRYPTO_SIGNATURE_H
