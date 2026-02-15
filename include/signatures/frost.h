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
 * @file frost.h
 * @brief FROST (Flexible Round-Optimized Schnorr Threshold) signatures with full Feldman VSS DKG.
 *
 * Implements t-of-n threshold signing where t participants cooperate to produce a standard
 * Ed25519 signature. The DKG (Distributed Key Generation) uses Feldman VSS so that no single
 * party ever holds the full signing key.
 */

#ifndef CRYPTO_FROST_H
#define CRYPTO_FROST_H

#include <types/crypto_frost_types.h>
#include <types/crypto_signature_t.h>

namespace Crypto::FROST
{
    /**
     * DKG Part 1: Generate a random polynomial and compute VSS shares + commitments.
     *
     * Each participant calls this independently, then distributes shares[j] to participant j
     * and broadcasts commitments publicly.
     *
     * @param identifier this participant's unique non-zero identifier (1..n)
     * @param max_signers total number of participants (n)
     * @param min_signers signing threshold (t)
     * @return (secret_shares, commitments) where shares[i] is for participant i+1
     */
    std::tuple<std::vector<crypto_frost_secret_share_t>, crypto_point_vector_t>
        dkg_part1(size_t identifier, size_t max_signers, size_t min_signers);

    /**
     * DKG Part 2: Verify a received share against the sender's public commitments.
     *
     * @param share the secret share received from another participant
     * @param sender_commitments the sender's VSS commitment points
     * @return true if the share is consistent with the commitments
     */
    bool dkg_verify_share(const crypto_frost_secret_share_t &share, const crypto_point_vector_t &sender_commitments);

    /**
     * DKG Part 3: Combine verified shares into a key package.
     *
     * Call this after verifying all received shares with dkg_verify_share().
     *
     * @param identifier this participant's unique identifier
     * @param received_shares shares received from all participants (including self)
     * @param all_commitments each participant's VSS commitments (indexed by participant)
     * @return the participant's key package (signing share, verifying share, group key)
     */
    crypto_frost_key_package_t dkg_part3(
        size_t identifier,
        const std::vector<crypto_frost_secret_share_t> &received_shares,
        const std::vector<crypto_point_vector_t> &all_commitments);

    /**
     * Build the public key package from all participants' commitments.
     *
     * @param max_signers total number of participants
     * @param all_commitments each participant's VSS commitments
     * @return the public key package (group key + verifying shares)
     */
    crypto_frost_public_key_package_t
        build_public_key_package(size_t max_signers, const std::vector<crypto_point_vector_t> &all_commitments);

    /**
     * Round 1: Generate nonce pair and commitment for signing.
     *
     * @param identifier this participant's identifier
     * @return (secret_nonce, public_commitment) -- nonce MUST be kept private
     */
    std::tuple<crypto_frost_nonce_t, crypto_frost_nonce_commitment_t> round1_commit(size_t identifier);

    /**
     * Round 2: Produce a signature share using the nonce and key package.
     *
     * @param message_digest the 32-byte hash of the message to sign
     * @param key_package this participant's key package from DKG
     * @param signer_nonces this participant's secret nonces from round 1
     * @param all_commitments all participating signers' nonce commitments
     * @return this participant's signature share
     */
    crypto_frost_signature_share_t round2_sign(
        const crypto_hash_t &message_digest,
        const crypto_frost_key_package_t &key_package,
        const crypto_frost_nonce_t &signer_nonces,
        const std::vector<crypto_frost_nonce_commitment_t> &all_commitments);

    /**
     * Aggregate signature shares into a final standard signature.
     *
     * Verifies each share individually and returns the combined signature.
     *
     * @param message_digest the 32-byte hash of the signed message
     * @param signature_shares all participating signers' signature shares
     * @param all_commitments all participating signers' nonce commitments
     * @param public_key_package the group's public key package
     * @return (success, signature) where success is true if all shares verified
     */
    std::tuple<bool, crypto_signature_t> aggregate(
        const crypto_hash_t &message_digest,
        const std::vector<crypto_frost_signature_share_t> &signature_shares,
        const std::vector<crypto_frost_nonce_commitment_t> &all_commitments,
        const crypto_frost_public_key_package_t &public_key_package);
} // namespace Crypto::FROST

#endif // CRYPTO_FROST_H
