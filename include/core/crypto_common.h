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
 * @file crypto_common.h
 * @brief Core cryptographic utility functions for the Crypto:: namespace.
 *
 * Provides the building blocks you will use most often: AES symmetric encryption,
 * Diffie-Hellman key derivation, stealth (one-time) address generation, key image
 * construction, and various mathematical helpers used internally by signatures and proofs.
 */

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <core/crypto_config.h>
#include <helpers/math_helpers.h>
#include <types/scalar_vector_t.h>

namespace Crypto
{
    /**
     * Initializes SIMD runtime dispatch for both the ed25519 and ranshaw libraries
     * using fast CPUID heuristics (IFMA > AVX2 > baseline).
     *
     * Thread-safe; only the first call executes. Subsequent calls are no-ops.
     * Call this once at program startup before any cryptographic operations.
     */
    void init();

    /**
     * Benchmarks all available SIMD backends for both the ed25519 and ranshaw
     * libraries and selects the fastest implementation per-function.
     *
     * Thread-safe; only the first call executes. Subsequent calls are no-ops.
     * Takes 1-2 seconds. Prefer this over init() when accurate timing matters
     * (e.g., before benchmarks or performance-sensitive workloads).
     */
    void autotune();

    /**
     * @brief AES-128-CBC symmetric encryption helpers for protecting sensitive data at rest.
     *
     * Uses PBKDF2 to derive an AES key from a password, then encrypts/decrypts the payload.
     * Input and output are hex-encoded strings so they are safe for text-based storage and transport.
     */
    namespace AES
    {
        /**
         * Decrypts a hex-encoded AES-128-CBC ciphertext using a password-derived key.
         *
         * The key is derived from @p password via PBKDF2 with the given iteration count.
         *
         * @param input hex-encoded ciphertext produced by encrypt()
         * @param password the password used to derive the decryption key
         * @param iterations PBKDF2 iteration count (higher = slower but more resistant to brute-force)
         * @return the decrypted plaintext string
         */
        std::string decrypt(
            const std::string &input,
            const std::string &password,
            size_t iterations = CRYPTO_PBKDF2_ITERATIONS);

        /**
         * Encrypts a plaintext string into a hex-encoded AES-128-CBC ciphertext using a password-derived key.
         *
         * The key is derived from @p password via PBKDF2 with the given iteration count.
         * Useful for protecting wallet seeds, secret keys, or other sensitive material at rest.
         *
         * @param input the plaintext string to encrypt
         * @param password the password used to derive the encryption key
         * @param iterations PBKDF2 iteration count (higher = slower but more resistant to brute-force)
         * @return hex-encoded ciphertext that can be decrypted with decrypt()
         */
        std::string encrypt(
            const std::string &input,
            const std::string &password,
            size_t iterations = CRYPTO_PBKDF2_ITERATIONS);
    } // namespace AES

    /**
     * Validates that the given value represents a point on the Ed25519 curve.
     *
     * @param value any type whose raw bytes might encode a curve point
     * @return true if the bytes decode to a valid curve point
     */
    template<typename T> bool check_point(const T &value)
    {
        return point_t::check(value);
    }

    /**
     * Validates that the given value is a properly reduced Ed25519 scalar (i.e., in [0, l)).
     *
     * @param value any type whose raw bytes might encode a scalar
     * @return true if the bytes represent a reduced scalar
     */
    template<typename T> bool check_scalar(const T &value)
    {
        return scalar_t::check(value);
    }

    /**
     * Converts a shared Diffie-Hellman derivation into a scalar, incorporating an output index
     * for sub-key generation: `Ds = H(D || output_index) mod l`.
     *
     * Each distinct @p output_index yields a different scalar, letting you derive many
     * independent sub-keys from a single shared secret.
     *
     * @param derivation the shared Diffie-Hellman derivation point (D = a * B)
     * @param output_index index for deriving distinct sub-keys (default 0)
     * @return the derivation scalar Ds
     */
    scalar_t derivation_to_scalar(const derivation_t &derivation, uint64_t output_index = 0);

    /**
     * Derives a one-time (stealth) public key from a derivation scalar and a recipient's
     * base public key: `P = Ds * G + B`.
     *
     * This is the core of stealth address generation -- the sender computes a unique
     * public key for each transaction output so that only the recipient can detect and
     * spend it.
     *
     * @param derivation_scalar the scalar Ds from derivation_to_scalar()
     * @param public_key the recipient's base public key B
     * @return the one-time public key P
     */
    public_key_t derive_public_key(const scalar_t &derivation_scalar, const public_key_t &public_key);

    /**
     * Derives the one-time secret key corresponding to derive_public_key(): `p = Ds + b mod l`.
     *
     * Only the recipient (who knows the base secret key @p secret_key) can compute this.
     * The result is the spending key for the stealth address.
     *
     * @param derivation_scalar the scalar Ds from derivation_to_scalar()
     * @param secret_key the recipient's base secret scalar b
     * @return the one-time secret key p
     */
    scalar_t derive_secret_key(const scalar_t &derivation_scalar, const scalar_t &secret_key);

    /**
     * Performs an ECDH key exchange to produce a shared derivation: `D = a * B`.
     *
     * Both parties can independently compute the same derivation -- the sender using
     * (their secret, recipient's public) and the recipient using (their secret, sender's public).
     * The result is the starting point for stealth address and sub-key derivation.
     *
     * @param public_key the other party's public key B
     * @param secret_key your secret scalar a
     * @return the shared derivation point D
     */
    derivation_t generate_key_derivation(const public_key_t &public_key, const scalar_t &secret_key);

    /**
     * Generates a key image: `I = x * Hp(P)`.
     *
     * A key image is a deterministic, unlinkable tag derived from a secret key. It lets you
     * detect if the same key has signed twice (double-spend prevention) without revealing
     * which public key in a ring was the real signer. Two signatures with the same key
     * image must have come from the same secret key.
     *
     * @param public_ephemeral the one-time public key P
     * @param secret_ephemeral the corresponding one-time secret scalar x
     * @return the key image I
     */
    key_image_t generate_key_image(const public_key_t &public_ephemeral, const scalar_t &secret_ephemeral);

    /**
     * Generates an alternative-form key image: `I = (1/x) * U`.
     *
     * This variant uses the secret scalar's inverse multiplied by the alternate base point U.
     * Produces a key image that serves the same double-spend detection purpose as
     * generate_key_image() but through a different algebraic construction.
     *
     * @param secret_ephemeral the one-time secret scalar x (must be non-zero)
     * @return the key image I
     */
    key_image_t generate_key_image_v2(const scalar_t &secret_ephemeral);

    /**
     * Generates a random key pair: `a = random_scalar(), A = a * G`.
     *
     * @warning These keys are **not** deterministically recoverable from a seed.
     * For wallet addresses, use generate_wallet_spend_keys() / generate_wallet_view_keys()
     * so that keys can be recovered from a mnemonic seed phrase.
     *
     * @return (public_key A, secret_scalar a) tuple
     */
    std::tuple<public_key_t, scalar_t> generate_keys();

    /**
     * Generates multiple random key pairs at once.
     *
     * @warning Same caveat as generate_keys() -- these are not seed-recoverable.
     *
     * @param count number of key pairs to generate
     * @return (vector of public keys, vector of secret scalars) tuple
     */
    std::tuple<std::vector<public_key_t>, std::vector<scalar_t>> generate_keys_m(size_t count = 1);

    /**
     * Recovers the recipient's base public key from a stealth address:
     * `B = P - H(D || output_index) * G`.
     *
     * This is the inverse of derive_public_key(). A recipient uses it to check whether a
     * given one-time public key @p public_ephemeral was intended for them by comparing the
     * recovered B against their known base public key.
     *
     * @param derivation the shared Diffie-Hellman derivation D
     * @param output_index the output index used during derivation
     * @param public_ephemeral the one-time public key P to test
     * @return the recovered base public key B
     */
    public_key_t underive_public_key(
        const derivation_t &derivation,
        uint64_t output_index,
        const public_key_t &public_ephemeral);
} // namespace Crypto

#endif // CRYPTO_COMMON_H
