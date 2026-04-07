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
 * @file rfc8032.h
 * @brief RFC-8032 Ed25519 signature generation (hedged) and verification (strict).
 *
 * This module produces and verifies signatures that satisfy the RFC-8032 §5.1.7
 * verification equation:
 *
 *     s * G == R + H(R || A || M) * A
 *
 * Any signature this module generates is therefore accepted by every spec-compliant
 * Ed25519 verifier (libsodium, OpenSSL, PyNaCl, ed25519-donna, etc.), and conversely
 * `check_signature` accepts any spec-conformant external signature byte-for-byte
 * (regression-tested against the RFC-8032 §7.1 Appendix A test vectors in
 * `src/test.cpp::test_signatures`).
 *
 * SIGNING SEMANTICS — hedged synthetic-nonce signing.
 *
 * RFC-8032 §5.1.6 specifies a *pure-deterministic* nonce derivation:
 * `α = SHA-512(prefix || M) mod L` where `prefix = SHA-512(seed)[32..64]`. This
 * module instead uses a *hedged* synthetic nonce:
 *
 *     α = H(M_digest || A || rand)
 *
 * stirring fresh entropy in alongside the message digest and public key. Both forms
 * produce mathematically valid Ed25519 signatures. (Throughout this module, `α` is
 * the secret nonce that produces `R = α·G`, and `k = H(R || A || M)` is the public
 * challenge — distinct symbols, distinct roles.) Hedged signing is endorsed by
 * FIPS 186-5 Appendix A and draft-irtf-cfrg-det-sigs-with-noise as an *improvement*
 * over pure-deterministic signing because it defeats fault-injection attacks where
 * the attacker re-runs the signer on identical inputs to leak intermediate state.
 *
 * The classic Ed25519 nonce-reuse key-extraction attack requires a repeated nonce
 * across two different messages signed by the same key. That cannot fire here:
 * `M_digest` is in the transcript, so different messages always produce different
 * `α` even if `scalar_t::random()` is catastrophically broken — the message digest
 * alone provides the deterministic anti-collision binding, and `rand` is purely
 * additive hedge.
 *
 * CONSEQUENCE: signatures are NOT byte-reproducible across calls (the same key+
 * message pair produces a fresh `(R, s)` each time), but every signature IS valid
 * Ed25519 and accepted by every spec verifier. If you need byte-reproducibility for
 * external test-vector matching, use a different library — this is a deliberate
 * design choice, not a bug.
 *
 * KEY API. The secret key parameter is a pre-derived `scalar_t`, NOT a 32-byte raw
 * seed. The entire `Crypto::` namespace is scalar-domain by convention. Callers who
 * start from a 32-byte seed must perform RFC-8032 §5.1.5 expansion themselves
 * (SHA-512 of the seed, clamping the lower half, deriving the public key from the
 * clamped scalar) before calling into this module.
 *
 * The sign and verify functions accept arbitrary-length messages (raw bytes), not
 * just 32-byte digests, since RFC-8032 hashes the message as part of the signing
 * equation.
 */

#ifndef CRYPTO_SIGNATURE_RFC8032_H
#define CRYPTO_SIGNATURE_RFC8032_H

#include <ed25519/signature_t.h>

namespace Crypto::RFC8032
{
    /**
     * Verifies an RFC-8032 Ed25519 signature over an arbitrary-length message.
     *
     * @param message pointer to the raw message bytes
     * @param message_length length of the message in bytes
     * @param public_key the signer's Ed25519 public key
     * @param signature the 64-byte signature to verify
     * @return true if the signature is valid for the given message and public key
     */
    bool check_signature(
        const void *message,
        size_t message_length,
        const public_key_t &public_key,
        const signature_t &signature);

    /**
     * Verifies an RFC-8032 Ed25519 signature (templated convenience overload).
     *
     * Accepts any type with `.data()` and `.size()` methods (e.g., std::string,
     * std::vector<uint8_t>, hash_t).
     *
     * @tparam T a type providing data() and size() accessors
     * @param message the message that was signed
     * @param public_key the signer's Ed25519 public key
     * @param signature the 64-byte signature to verify
     * @return true if the signature is valid
     */
    template<typename T>
    bool check_signature(const T &message, const public_key_t &public_key, const signature_t &signature)
    {
        return check_signature(message.data(), message.size(), public_key, signature);
    }

    /**
     * Generates a valid RFC-8032 Ed25519 signature over an arbitrary-length message
     * using hedged synthetic-nonce signing (see the file-level doc block for the
     * full rationale).
     *
     * The nonce is derived as `α = H(SHA-512(M) || A || scalar_t::random())` and
     * combined with the standard challenge `k = SHA-512(R || A || M) mod L` to
     * produce `s = α + k·a`. The resulting `(R, s)` satisfies the §5.1.7 verification
     * equation and is accepted by every spec-compliant Ed25519 verifier.
     *
     * Signatures are NOT byte-reproducible across calls — each invocation produces a
     * fresh `(R, s)` pair. This is intentional (anti fault-injection hedge per
     * FIPS 186-5 Appendix A); see the file header for the full security argument.
     *
     * @param message pointer to the raw message bytes
     * @param message_length length of the message in bytes
     * @param secret_key the pre-derived signing scalar (NOT a raw 32-byte seed —
     *                   the entire library is scalar-domain by convention)
     * @return the 64-byte Ed25519 signature
     */
    signature_t generate_signature(const void *message, size_t message_length, const scalar_t &secret_key);

    /**
     * Generates a hedged RFC-8032 Ed25519 signature (templated convenience overload).
     *
     * @tparam T a type providing data() and size() accessors
     * @param message the message to sign
     * @param secret_key the pre-derived signing scalar
     * @return the 64-byte Ed25519 signature
     */
    template<typename T> signature_t generate_signature(const T &message, const scalar_t &secret_key)
    {
        return generate_signature(message.data(), message.size(), secret_key);
    }
} // namespace Crypto::RFC8032

#endif
