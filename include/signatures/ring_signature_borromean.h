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
 * @file ring_signature_borromean.h
 * @brief Borromean ring signature generation and verification.
 *
 * A Borromean ring signature lets you prove that you know the secret key for *one* of the
 * public keys in a ring, without revealing *which* one. The key image parameter makes the
 * signature **linkable**: if the same secret key signs two different messages, both
 * signatures will share the same key image, enabling double-spend detection without
 * breaking signer anonymity.
 */

#ifndef CRYPTO_RING_SIGNATURE_BORROMEAN_H
#define CRYPTO_RING_SIGNATURE_BORROMEAN_H

#include <types/crypto_borromean_signature_t.h>

namespace Crypto::RingSignature::Borromean
{
    /**
     * Verifies a Borromean ring signature.
     *
     * Checks that the signature is valid for the given message, key image, and set of
     * public keys. The verifier does not learn which ring member actually signed.
     *
     * @param message_digest 32-byte hash of the signed message
     * @param key_image the key image I -- must match the one embedded in the signature
     * @param public_keys the ring of public keys (one of which is the real signer)
     * @param borromean_signature the Borromean ring signature to verify
     * @return true if the signature is valid
     */
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_borromean_signature_t &borromean_signature);

    /**
     * Generates a Borromean ring signature, auto-detecting the signer's position.
     *
     * Scans @p public_keys in constant time to find the index whose public key matches
     * the one derived from @p secret_ephemeral. The resulting signature hides which
     * member of the ring actually signed, while the embedded key image allows linkability.
     *
     * @param message_digest 32-byte hash of the message to sign
     * @param secret_ephemeral the signer's one-time secret scalar
     * @param public_keys the ring of public keys to sign against
     * @return (success, signature) -- success is false if the secret key does not match any ring member
     */
    std::tuple<bool, crypto_borromean_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys);

    /**
     * Generates a Borromean ring signature with an explicit signer index.
     *
     * Same as the auto-detect overload, but you provide @p real_output_index directly.
     * The index is still validated against the secret key for safety.
     *
     * @param message_digest 32-byte hash of the message to sign
     * @param secret_ephemeral the signer's one-time secret scalar
     * @param public_keys the ring of public keys to sign against
     * @param real_output_index position of the real signer's public key in @p public_keys
     * @return (success, signature) tuple
     */
    std::tuple<bool, crypto_borromean_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index);
} // namespace Crypto::RingSignature::Borromean

#endif // CRYPTO_RING_SIGNATURE_BORROMEAN_H
