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
 * @file crypto_constants.h
 * @brief Domain-separated salt constants for all cryptographic subsystems.
 *
 * Every signature scheme, proof system, and key derivation routine in this library needs
 * its own set of "nothing-up-my-sleeve" constants to prevent cross-protocol scalar reuse
 * attacks. We generate them deterministically from a single seed domain (SALT_DOMAIN) by
 * feeding sequential indices through iterated SHA-3 hashing (sha3_slow). This guarantees
 * that each subsystem operates in its own hash domain while keeping the constants fully
 * reproducible and auditable.
 *
 * INITIALIZATION: All constants use Construct On First Use (static local inside an inline
 * function) to avoid the C++ Static Initialization Order Fiasco. The SALT_DOMAIN seed
 * and generator functions are similarly protected. This guarantees correct initialization
 * order regardless of which translation unit first references a constant.
 *
 * INDEX MAP (contiguous, no gaps):
 *   0     DERIVATION_DOMAIN_0        14    BULLETPROOFS_DOMAIN_2
 *   1     SPEND_KEY_DOMAIN_0         15    BULLETPROOFS_PLUS_DOMAIN_0
 *   2     VIEW_KEY_DOMAIN_0          16    BULLETPROOFS_PLUS_DOMAIN_1
 *   3     SIGNATURE_DOMAIN_0         17    BULLETPROOFS_PLUS_DOMAIN_2
 *   4     BORROMEAN_DOMAIN_0         18    OUTPUT_PROOF_DOMAIN
 *   5     CLSAG_DOMAIN_0             19    TRANSCRIPT_BASE
 *   6     CLSAG_DOMAIN_1             20    BULLETPROOFS_PP_DOMAIN_0
 *   7     CLSAG_DOMAIN_2             21    BULLETPROOFS_PP_DOMAIN_1
 *   8     DOMAIN_COMMITMENT_MASK_0   22    BULLETPROOFS_PP_DOMAIN_2
 *   9     DOMAIN_AMOUNT_MASK_0       23    MLSAG_DOMAIN_0
 *   10    TRIPTYCH_DOMAIN_0          24    MLSAG_DOMAIN_1
 *   11    TRIPTYCH_DOMAIN_1          25    DLEQ_DOMAIN_0
 *   12    BULLETPROOFS_DOMAIN_0      26    ADAPTER_DOMAIN_0
 *   13    BULLETPROOFS_DOMAIN_1      27    VRF_DOMAIN_0
 */

#ifndef CRYPTO_CONSTANTS_H
#define CRYPTO_CONSTANTS_H

#include <types/hash_t.h>
#include <types/scalar_t.h>

/** @brief The root seed from which all domain-separated salt constants are derived. */
inline const scalar_t &SALT_DOMAIN_ref()
{
    static const auto value = scalar_t("202053504f4e534f52454420425920444f4e5554532041524520474f4f442020");
    return value;
}

// Backward-compatible name (evaluates to a reference, usable everywhere the old const was)
#define SALT_DOMAIN (SALT_DOMAIN_ref())

/**
 * Generates a deterministic salt scalar for the given index.
 *
 * Computes `sha3_slow(SALT_DOMAIN, index)` and reduces the result to a scalar mod l.
 * The iterated hashing makes it computationally infeasible to find index collisions.
 *
 * @param index a unique sequential identifier for this constant
 * @return a deterministic, unpredictable scalar
 */
static inline scalar_t generate_salt_scalar(size_t index)
{
    return hash_t::sha3_slow(SALT_DOMAIN, index).scalar();
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
static inline point_t generate_salt_point(size_t index)
{
    return hash_t::sha3_slow(SALT_DOMAIN, index).point();
}

// ============================================================================
// Construct On First Use macro: each constant is a static local inside an
// inline function, guaranteeing initialization before first use regardless
// of translation unit ordering.
// ============================================================================
#define DEFINE_SALT_SCALAR_CONSTANT(name, index)               \
    inline const scalar_t &name##_ref()                        \
    {                                                          \
        static const auto value = generate_salt_scalar(index); \
        return value;                                          \
    }                                                          \
    static const scalar_t &name = name##_ref()

#define DEFINE_SALT_POINT_CONSTANT(name, index)               \
    inline const point_t &name##_ref()                        \
    {                                                         \
        static const auto value = generate_salt_point(index); \
        return value;                                         \
    }                                                         \
    static const point_t &name = name##_ref()

/**
 * @name Domain Salt Constants
 * @brief Per-subsystem hash salts that prevent cross-protocol scalar reuse.
 *
 * Each cryptographic subsystem (signatures, proofs, key derivation, etc.) uses its own
 * domain constants so that identical inputs in different contexts never produce the same
 * intermediate scalars or points. This is critical for security -- without domain separation,
 * a value computed for one scheme could be replayed or exploited in another.
 *
 * All indices are contiguous (0-48) with no gaps.
 * @{
 */

/** @brief Key derivation (ECDH shared secret to derivation scalar). */
DEFINE_SALT_SCALAR_CONSTANT(DERIVATION_DOMAIN_0, 0);

/** @brief Spend key derivation from wallet seed. */
DEFINE_SALT_SCALAR_CONSTANT(SPEND_KEY_DOMAIN_0, 1);

/** @brief View key derivation from wallet seed. */
DEFINE_SALT_SCALAR_CONSTANT(VIEW_KEY_DOMAIN_0, 2);

/** @brief Basic Ed25519 signature challenge hash. */
DEFINE_SALT_SCALAR_CONSTANT(SIGNATURE_DOMAIN_0, 3);

/** @brief Borromean ring signature challenge computation. */
DEFINE_SALT_SCALAR_CONSTANT(BORROMEAN_DOMAIN_0, 4);

/** @brief CLSAG ring signature -- primary challenge hash. */
DEFINE_SALT_SCALAR_CONSTANT(CLSAG_DOMAIN_0, 5);

/** @brief CLSAG ring signature -- key aggregation coefficient. */
DEFINE_SALT_SCALAR_CONSTANT(CLSAG_DOMAIN_1, 6);

/** @brief CLSAG ring signature -- commitment aggregation coefficient. */
DEFINE_SALT_SCALAR_CONSTANT(CLSAG_DOMAIN_2, 7);

/** @brief RingCT commitment mask derivation (hides blinding factor). */
DEFINE_SALT_SCALAR_CONSTANT(DOMAIN_COMMITMENT_MASK_0, 8);

/** @brief RingCT amount mask derivation (hides encrypted amounts). */
DEFINE_SALT_SCALAR_CONSTANT(DOMAIN_AMOUNT_MASK_0, 9);

/** @brief Triptych ring signature -- challenge scalar. */
DEFINE_SALT_SCALAR_CONSTANT(TRIPTYCH_DOMAIN_0, 10);

/** @brief Triptych ring signature -- auxiliary generator point. */
DEFINE_SALT_POINT_CONSTANT(TRIPTYCH_DOMAIN_1, 11);

/** @brief Bulletproofs range proof -- challenge scalar. */
DEFINE_SALT_SCALAR_CONSTANT(BULLETPROOFS_DOMAIN_0, 12);

/** @brief Bulletproofs range proof -- first auxiliary generator point. */
DEFINE_SALT_POINT_CONSTANT(BULLETPROOFS_DOMAIN_1, 13);

/** @brief Bulletproofs range proof -- second auxiliary generator point. */
DEFINE_SALT_POINT_CONSTANT(BULLETPROOFS_DOMAIN_2, 14);

/** @brief Bulletproofs+ range proof -- challenge scalar. */
DEFINE_SALT_SCALAR_CONSTANT(BULLETPROOFS_PLUS_DOMAIN_0, 15);

/** @brief Bulletproofs+ range proof -- first auxiliary generator point. */
DEFINE_SALT_POINT_CONSTANT(BULLETPROOFS_PLUS_DOMAIN_1, 16);

/** @brief Bulletproofs+ range proof -- second auxiliary generator point. */
DEFINE_SALT_POINT_CONSTANT(BULLETPROOFS_PLUS_DOMAIN_2, 17);

/** @brief Output ownership/audit proof domain. */
DEFINE_SALT_SCALAR_CONSTANT(OUTPUT_PROOF_DOMAIN, 18);

/** @brief Base scalar for Fiat-Shamir transcript initialization. */
DEFINE_SALT_SCALAR_CONSTANT(TRANSCRIPT_BASE, 19);

/** @brief Bulletproofs++ reciprocal range proof -- challenge scalar. */
DEFINE_SALT_SCALAR_CONSTANT(BULLETPROOFS_PP_DOMAIN_0, 20);

/** @brief Bulletproofs++ reciprocal range proof -- first auxiliary generator point. */
DEFINE_SALT_POINT_CONSTANT(BULLETPROOFS_PP_DOMAIN_1, 21);

/** @brief Bulletproofs++ reciprocal range proof -- second auxiliary generator point. */
DEFINE_SALT_POINT_CONSTANT(BULLETPROOFS_PP_DOMAIN_2, 22);

/** @brief MLSAG ring signature -- challenge chain. */
DEFINE_SALT_SCALAR_CONSTANT(MLSAG_DOMAIN_0, 23);

/** @brief MLSAG ring signature -- commitment nonce derivation. */
DEFINE_SALT_SCALAR_CONSTANT(MLSAG_DOMAIN_1, 24);

/** @brief DLEQ proof challenge hash. */
DEFINE_SALT_SCALAR_CONSTANT(DLEQ_DOMAIN_0, 25);

/** @brief Adapter signature challenge hash. */
DEFINE_SALT_SCALAR_CONSTANT(ADAPTER_DOMAIN_0, 26);

/** @brief VRF native challenge hash. */
DEFINE_SALT_SCALAR_CONSTANT(VRF_DOMAIN_0, 27);

/** @} */

#endif
