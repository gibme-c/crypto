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
 * @file ring_signature_mlsag.h
 * @brief Multilayered Linkable Spontaneous Anonymous Group (MLSAG) ring signatures.
 *
 * MLSAG is the predecessor to CLSAG, using per-column response scalars instead of
 * CLSAG's aggregated single scalar. This results in roughly twice the signature size
 * when used with commitments (M=2 columns), but provides the same security guarantees:
 * signer ambiguity within the ring plus linkability via a key image.
 *
 * Two modes are supported:
 * - **Without commitments** (M=1): one scalar per ring member for the key column.
 * - **With commitments** (M=2): two scalars per ring member for key + commitment columns.
 */

#ifndef CRYPTO_RING_SIGNATURE_MLSAG_H
#define CRYPTO_RING_SIGNATURE_MLSAG_H

#include <types/crypto_mlsag_signature_t.h>

namespace Crypto::RingSignature::MLSAG
{
    /**
     * Verifies an MLSAG ring signature.
     *
     * When @p commitments is non-empty, the verification also checks that the signature
     * binds to the provided Pedersen commitments (i.e., the signer knew the blinding
     * factor difference between the real commitment and the pseudo-commitment stored
     * in the signature).
     *
     * @param message_digest 32-byte hash of the signed message
     * @param key_image the key image I for linkability / double-spend detection
     * @param public_keys the ring of public keys
     * @param signature the MLSAG signature to verify
     * @param commitments optional per-ring-member Pedersen commitments for confidential amounts
     * @return true if the signature is valid
     */
    bool check_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_key_image_t &key_image,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_mlsag_signature_t &signature,
        const std::vector<crypto_pedersen_commitment_t> &commitments = {});

    /**
     * Generates an MLSAG ring signature, auto-detecting the signer's position.
     *
     * For plain ring signatures (no confidential amounts), omit the commitment parameters.
     * For commitment-binding signatures used in privacy-preserving transactions, supply:
     * - @p input_blinding_factor: the blinding factor of the real input commitment
     * - @p public_commitments: Pedersen commitments for every ring member
     * - @p pseudo_blinding_factor: the blinding factor of the pseudo (output-side) commitment
     * - @p pseudo_commitment: the pseudo-commitment itself (C' = pseudo_blinding_factor * G + amount * H)
     *
     * @param message_digest 32-byte hash of the message to sign
     * @param secret_ephemeral the signer's one-time secret scalar
     * @param public_keys the ring of public keys
     * @param input_blinding_factor blinding factor for the real input's Pedersen commitment (default: zero)
     * @param public_commitments per-ring-member Pedersen commitments (default: empty = no commitment binding)
     * @param pseudo_blinding_factor blinding factor for the pseudo-commitment (default: zero)
     * @param pseudo_commitment the pseudo-commitment point (default: identity)
     * @return (success, signature) -- success is false if the secret key does not match any ring member
     */
    std::tuple<bool, crypto_mlsag_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        const crypto_blinding_factor_t &input_blinding_factor = Crypto::ZERO,
        const std::vector<crypto_pedersen_commitment_t> &public_commitments = {},
        const crypto_blinding_factor_t &pseudo_blinding_factor = Crypto::ZERO,
        const crypto_pedersen_commitment_t &pseudo_commitment = Crypto::Z);

    /**
     * Generates an MLSAG ring signature with an explicit signer index.
     *
     * Same as the auto-detect overload, but you provide @p real_output_index directly.
     * The index is still validated against the secret key for safety.
     *
     * @param message_digest 32-byte hash of the message to sign
     * @param secret_ephemeral the signer's one-time secret scalar
     * @param public_keys the ring of public keys
     * @param real_output_index position of the real signer's public key in @p public_keys
     * @param input_blinding_factor blinding factor for the real input's Pedersen commitment (default: zero)
     * @param public_commitments per-ring-member Pedersen commitments (default: empty)
     * @param pseudo_blinding_factor blinding factor for the pseudo-commitment (default: zero)
     * @param pseudo_commitment the pseudo-commitment point (default: identity)
     * @return (success, signature) tuple
     */
    std::tuple<bool, crypto_mlsag_signature_t> generate_ring_signature(
        const crypto_hash_t &message_digest,
        const crypto_scalar_t &secret_ephemeral,
        const std::vector<crypto_public_key_t> &public_keys,
        size_t real_output_index,
        const crypto_blinding_factor_t &input_blinding_factor = Crypto::ZERO,
        const std::vector<crypto_pedersen_commitment_t> &public_commitments = {},
        const crypto_blinding_factor_t &pseudo_blinding_factor = Crypto::ZERO,
        const crypto_pedersen_commitment_t &pseudo_commitment = Crypto::Z);
} // namespace Crypto::RingSignature::MLSAG


#endif // CRYPTO_RING_SIGNATURE_MLSAG_H
