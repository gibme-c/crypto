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
//
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

/**
 * @file triptych.h
 * @brief Triptych ring signatures with logarithmic proof size.
 *
 * Triptych is an advanced linkable ring signature scheme whose proof size grows
 * **logarithmically** with the ring size (O(log N) group elements), compared to the
 * linear O(N) scaling of Borromean/CLSAG. This makes it practical to use very large
 * rings (e.g., 128 or 256 members) for stronger signer anonymity without a proportional
 * increase in signature size or verification time.
 *
 * Like CLSAG, Triptych natively supports Pedersen commitment binding for confidential
 * transaction amounts.
 *
 * @note The ring size must be a power of two.
 */

#ifndef CRYPTO_PROOFS_TRIPTYCH_H
#define CRYPTO_PROOFS_TRIPTYCH_H

#include <triptych/triptych_signature_t.h>

namespace Crypto::RingSignature::Triptych
{
    /**
     * Verifies a Triptych ring signature.
     *
     * Checks that the signature is valid for the given message, key image, ring of public
     * keys, and per-member Pedersen commitments. Verification cost is O(N) point operations
     * (dominated by the multi-scalar multiplication over the ring), but the signature itself
     * is only O(log N) in size.
     *
     * @param message_digest 32-byte hash of the signed message
     * @param key_image the key image I for linkability / double-spend detection
     * @param public_keys the ring of public keys (must be a power-of-two length)
     * @param signature the Triptych signature to verify
     * @param commitments per-ring-member Pedersen commitments
     * @return true if the signature is valid
     */
    bool check_ring_signature(
        const hash_t &message_digest,
        const key_image_t &key_image,
        const std::vector<public_key_t> &public_keys,
        const triptych_signature_t &signature,
        const std::vector<pedersen_commitment_t> &commitments);

    /**
     * Generates a complete Triptych ring signature, auto-detecting the signer's position.
     *
     * Scans @p public_keys to find the index matching @p secret_ephemeral, then produces
     * a linkable ring signature with commitment binding. The ring size must be a power of two.
     *
     * @param message_digest 32-byte hash of the message to sign
     * @param secret_ephemeral the signer's one-time secret scalar
     * @param public_keys the ring of public keys (power-of-two length)
     * @param input_blinding_factor blinding factor of the real input's Pedersen commitment
     * @param input_commitments per-ring-member Pedersen commitments
     * @param pseudo_blinding_factor blinding factor of the pseudo-commitment
     * @param pseudo_commitment the pseudo-commitment point
     * @return (success, signature) -- success is false if the secret key does not match any ring member
     */
    std::tuple<bool, triptych_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys,
        const blinding_factor_t &input_blinding_factor,
        const std::vector<pedersen_commitment_t> &input_commitments,
        const blinding_factor_t &pseudo_blinding_factor,
        const pedersen_commitment_t &pseudo_commitment);

    /**
     * Generates a complete Triptych ring signature with an explicit signer index.
     *
     * Same as the auto-detect overload, but you provide @p real_output_index directly.
     * The index is still validated against the secret key for safety.
     *
     * @param message_digest 32-byte hash of the message to sign
     * @param secret_ephemeral the signer's one-time secret scalar
     * @param public_keys the ring of public keys (power-of-two length)
     * @param real_output_index position of the real signer's public key in @p public_keys
     * @param input_blinding_factor blinding factor of the real input's Pedersen commitment
     * @param input_commitments per-ring-member Pedersen commitments
     * @param pseudo_blinding_factor blinding factor of the pseudo-commitment
     * @param pseudo_commitment the pseudo-commitment point
     * @return (success, signature) tuple
     */
    std::tuple<bool, triptych_signature_t> generate_ring_signature(
        const hash_t &message_digest,
        const scalar_t &secret_ephemeral,
        const std::vector<public_key_t> &public_keys,
        size_t real_output_index,
        const blinding_factor_t &input_blinding_factor,
        const std::vector<pedersen_commitment_t> &input_commitments,
        const blinding_factor_t &pseudo_blinding_factor,
        const pedersen_commitment_t &pseudo_commitment);

} // namespace Crypto::RingSignature::Triptych
#endif // CRYPTO_PROOFS_TRIPTYCH_H
