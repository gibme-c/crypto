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
 * @brief Strict RFC-8032 Ed25519 signature generation and verification.
 *
 * Unlike the custom variant in signature.h (which takes a pre-derived scalar), this
 * implementation follows RFC-8032 exactly: it uses the raw 32-byte secret key seed and
 * derives the signing scalar and deterministic nonce internally via SHA-512. This means
 * signatures are fully deterministic for a given (seed, message) pair and are interoperable
 * with any standard Ed25519 implementation.
 *
 * The sign and verify functions accept arbitrary-length messages (raw bytes), not just
 * 32-byte digests, since RFC-8032 hashes the message as part of the signing equation.
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
     * Generates a deterministic RFC-8032 Ed25519 signature over an arbitrary-length message.
     *
     * The nonce is derived deterministically from SHA-512(seed_prefix || message), so
     * signing the same message with the same key always produces the identical signature.
     *
     * @param message pointer to the raw message bytes
     * @param message_length length of the message in bytes
     * @param secret_key the 32-byte secret key seed (not a pre-derived scalar)
     * @return the 64-byte Ed25519 signature
     */
    signature_t generate_signature(const void *message, size_t message_length, const scalar_t &secret_key);

    /**
     * Generates a deterministic RFC-8032 Ed25519 signature (templated convenience overload).
     *
     * @tparam T a type providing data() and size() accessors
     * @param message the message to sign
     * @param secret_key the 32-byte secret key seed
     * @return the 64-byte Ed25519 signature
     */
    template<typename T> signature_t generate_signature(const T &message, const scalar_t &secret_key)
    {
        return generate_signature(message.data(), message.size(), secret_key);
    }
} // namespace Crypto::RFC8032

#endif
