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
 * @file secret_key_t.h
 * @brief RFC-8032 Ed25519 secret key type (32-byte seed with derived scalar and public key).
 *
 * An Ed25519 secret key is a raw 32-byte random seed. Per RFC-8032, the usable signing
 * scalar is derived by hashing the seed with SHA-512 and clamping the lower 32 bytes
 * (clearing bits 0, 1, 2, 253, 254, 255 and setting bit 254). The corresponding public
 * key is then scalar * G. This type handles that derivation automatically on construction.
 */

#ifndef SECRET_KEY_T_H
#define SECRET_KEY_T_H

#include <types/point_t.h>
#include <types/scalar_t.h>

/**
 * An RFC-8032 Ed25519 secret key (32-byte seed).
 *
 * On construction, the seed is hashed via SHA-512 and clamped to produce the signing
 * scalar, which is cached internally. You can retrieve the scalar with scalar() and
 * the corresponding public key point with point(). The raw 32 bytes are the seed itself,
 * not the derived scalar.
 */
struct secret_key_t final : SerializablePod<32>
{
    secret_key_t() = default;

    secret_key_t(std::initializer_list<unsigned char> input);

    explicit secret_key_t(const std::vector<unsigned char> &input);

    explicit secret_key_t(const std::string &s);

    JSON_STRING_CONSTRUCTOR(secret_key_t, fromJSON)

    operator scalar_t() const;

    bool operator==(const secret_key_t &other) const;

    bool operator!=(const secret_key_t &other) const;

    /**
     * Returns the clamped signing scalar derived from the seed via SHA-512, as specified
     * by RFC-8032. This is the scalar you use for signing operations and key image generation.
     * @return the derived Ed25519 scalar
     */
    [[nodiscard]] scalar_t scalar() const;

    /**
     * Returns the public key (scalar * G) corresponding to this secret key.
     * @return the Ed25519 public key point
     */
    [[nodiscard]] point_t point() const;

  protected:
    void load_hook() override;

    scalar_t _scalar;
};

#endif
