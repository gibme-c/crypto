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
 * @file crypto_constants.h
 * @brief Domain-separated salt constants for all cryptographic subsystems.
 *
 * Every signature scheme, proof system, and key derivation routine in this library needs
 * its own set of "nothing-up-my-sleeve" constants to prevent cross-protocol scalar reuse
 * attacks. We generate them deterministically from a single seed domain (SALT_DOMAIN) by
 * feeding sequential indices through iterated SHA-3 hashing (sha3_slow). This guarantees
 * that each subsystem operates in its own hash domain while keeping the constants fully
 * reproducible and auditable.
 */

#ifndef CRYPTO_CONSTANTS_H
#define CRYPTO_CONSTANTS_H

#include <types/crypto_hash_t.h>
#include <types/crypto_scalar_t.h>

/** @brief The root seed from which all domain-separated salt constants are derived. */
const auto SALT_DOMAIN = crypto_scalar_t("202053504f4e534f52454420425920444f4e5554532041524520474f4f442020");

/**
 * Generates a deterministic salt scalar for the given index.
 *
 * Computes `sha3_slow(SALT_DOMAIN, index)` and reduces the result to a scalar mod l.
 * The iterated hashing makes it computationally infeasible to find index collisions.
 *
 * @param index a unique sequential identifier for this constant
 * @return a deterministic, unpredictable scalar
 */
static inline crypto_scalar_t generate_salt_scalar(size_t index)
{
    return crypto_hash_t::sha3_slow(SALT_DOMAIN, index).scalar();
}

/**
 * Generates a deterministic salt point for the given index.
 *
 * Like generate_salt_scalar() but maps the hash output to a curve point via hash-to-point.
 * Used when a subsystem needs a "nothing-up-my-sleeve" generator point rather than a scalar.
 *
 * @param index a unique sequential identifier for this constant
 * @return a deterministic, unpredictable curve point
 */
static inline crypto_point_t generate_salt_point(size_t index)
{
    return crypto_hash_t::sha3_slow(SALT_DOMAIN, index).point();
}

/**
 * @name Domain Salt Constants
 * @brief Per-subsystem hash salts that prevent cross-protocol scalar reuse.
 *
 * Each cryptographic subsystem (signatures, proofs, key derivation, etc.) uses its own
 * domain constants so that identical inputs in different contexts never produce the same
 * intermediate scalars or points. This is critical for security -- without domain separation,
 * a value computed for one scheme could be replayed or exploited in another.
 * @{
 */

/** @brief Key derivation (ECDH shared secret to derivation scalar). */
const auto DERIVATION_DOMAIN_0 = generate_salt_scalar(0);

/** @brief Spend key derivation from wallet seed. */
const auto SPEND_KEY_DOMAIN_0 = generate_salt_scalar(1);

/** @brief View key derivation from wallet seed. */
const auto VIEW_KEY_DOMAIN_0 = generate_salt_scalar(2);

/** @brief Basic Ed25519 signature challenge hash. */
const auto SIGNATURE_DOMAIN_0 = generate_salt_scalar(3);

/** @brief Borromean ring signature challenge computation. */
const auto BORROMEAN_DOMAIN_0 = generate_salt_scalar(4);

/** @brief CLSAG ring signature -- primary challenge hash. */
const auto CLSAG_DOMAIN_0 = generate_salt_scalar(5);

/** @brief CLSAG ring signature -- key aggregation coefficient. */
const auto CLSAG_DOMAIN_1 = generate_salt_scalar(6);

/** @brief CLSAG ring signature -- commitment aggregation coefficient. */
const auto CLSAG_DOMAIN_2 = generate_salt_scalar(7);

/** @brief RingCT commitment mask derivation (hides blinding factor). */
const auto DOMAIN_COMMITMENT_MASK_0 = generate_salt_scalar(8);

/** @brief RingCT amount mask derivation (hides encrypted amounts). */
const auto DOMAIN_AMOUNT_MASK_0 = generate_salt_scalar(9);

/** @brief Triptych ring signature -- challenge scalar. */
const auto TRIPTYCH_DOMAIN_0 = generate_salt_scalar(10);

/** @brief Triptych ring signature -- auxiliary generator point. */
const auto TRIPTYCH_DOMAIN_1 = generate_salt_point(11);

/** @brief Bulletproofs range proof -- challenge scalar. */
const auto BULLETPROOFS_DOMAIN_0 = generate_salt_scalar(12);

/** @brief Bulletproofs range proof -- first auxiliary generator point. */
const auto BULLETPROOFS_DOMAIN_1 = generate_salt_point(13);

/** @brief Bulletproofs range proof -- second auxiliary generator point. */
const auto BULLETPROOFS_DOMAIN_2 = generate_salt_point(14);

/** @brief Bulletproofs+ range proof -- challenge scalar. */
const auto BULLETPROOFS_PLUS_DOMAIN_0 = generate_salt_scalar(15);

/** @brief Bulletproofs+ range proof -- first auxiliary generator point. */
const auto BULLETPROOFS_PLUS_DOMAIN_1 = generate_salt_point(16);

/** @brief Bulletproofs+ range proof -- second auxiliary generator point. */
const auto BULLETPROOFS_PLUS_DOMAIN_2 = generate_salt_point(17);

/** @brief Output ownership/audit proof domain. */
const auto OUTPUT_PROOF_DOMAIN = generate_salt_scalar(18);

/** @brief Base scalar for Fiat-Shamir transcript initialization. */
const auto TRANSCRIPT_BASE = generate_salt_scalar(19);

/** @brief Bulletproofs++ reciprocal range proof -- challenge scalar. */
const auto BULLETPROOFS_PP_DOMAIN_0 = generate_salt_scalar(20);

/** @brief Bulletproofs++ reciprocal range proof -- first auxiliary generator point. */
const auto BULLETPROOFS_PP_DOMAIN_1 = generate_salt_point(21);

/** @brief Bulletproofs++ reciprocal range proof -- second auxiliary generator point. */
const auto BULLETPROOFS_PP_DOMAIN_2 = generate_salt_point(22);

/** @} */

#endif
