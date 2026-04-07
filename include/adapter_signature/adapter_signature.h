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
 * @file adapter_signature.h
 * @brief Schnorr-based adapter signatures for trustless atomic swaps.
 *
 * An adapter signature is a pre-signature locked to a statement point Y = yG.
 * Once the witness scalar y is revealed, the pre-signature can be "adapted" into
 * a valid standard Ed25519 signature. Conversely, publishing the adapted signature
 * lets the counterparty extract the witness y.
 */

#ifndef CRYPTO_ADAPTER_SIGNATURE_H
#define CRYPTO_ADAPTER_SIGNATURE_H

#include <adapter_signature/adapted_signature_t.h>
#include <adapter_signature/adapter_signature_t.h>

namespace Crypto::AdapterSignature
{
    /**
     * Creates an adapter pre-signature locked to a statement point Y.
     *
     * @param message_digest the 32-byte hash of the message to sign
     * @param secret_key the signer's secret scalar
     * @param statement_Y the statement point (Y = yG where y is the witness)
     * @return the adapter pre-signature
     */
    adapter_signature_t pre_sign(const hash_t &message_digest, const scalar_t &secret_key, const point_t &statement_Y);

    /**
     * Verifies that an adapter pre-signature is well-formed and consistent with the statement Y.
     *
     * @param message_digest the 32-byte hash of the signed message
     * @param public_key the signer's public key
     * @param statement_Y the statement point
     * @param pre_signature the adapter pre-signature to verify
     * @return true if the pre-signature is valid
     */
    bool check_pre_signature(
        const hash_t &message_digest,
        const public_key_t &public_key,
        const point_t &statement_Y,
        const adapter_signature_t &pre_signature);

    /**
     * Adapts a pre-signature into a Schnorr (R', s) signature using the witness scalar.
     *
     * @param pre_signature the adapter pre-signature
     * @param witness_y the witness scalar (such that statement_Y = witness_y * G)
     * @return the adapted Schnorr signature under the adapter Fiat-Shamir domain
     */
    adapted_signature_t adapt(const adapter_signature_t &pre_signature, const scalar_t &witness_y);

    /**
     * Verifies an adapted signature (produced by adapt()) against the signer's public key.
     *
     * @param message_digest the 32-byte hash of the signed message
     * @param public_key the signer's public key
     * @param signature the adapted signature (produced by adapt())
     * @return true if the adapted signature is valid
     */
    bool check_adapted_signature(
        const hash_t &message_digest,
        const public_key_t &public_key,
        const adapted_signature_t &signature);

    /**
     * Extracts the witness scalar from a pre-signature and its adapted signature.
     *
     * @param pre_signature the original adapter pre-signature
     * @param signature the adapted signature
     * @param statement_Y the statement point (for verification)
     * @return the extracted witness scalar y
     */
    scalar_t extract(
        const adapter_signature_t &pre_signature,
        const adapted_signature_t &signature,
        const point_t &statement_Y);

} // namespace Crypto::AdapterSignature

#endif // CRYPTO_ADAPTER_SIGNATURE_H
