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
 * @file crypto_point_t.h
 * @brief Ed25519 elliptic curve point type with cached internal representations.
 *
 * Provides the fundamental curve point abstraction used throughout the library.
 * Points are 32-byte compressed Ed25519 coordinates that automatically cache their
 * internal ge_p2, ge_p3, and ge_cached forms on construction, trading a bit of extra
 * memory for significantly faster arithmetic when the same point is reused.
 */

#ifndef CRYPTO_POINT_T
#define CRYPTO_POINT_T

#include <ed25519.h>
#include <helpers/debug_helper.h>
#include <serialization.h>

/**
 * An Ed25519 elliptic curve point (32-byte compressed encoding).
 *
 * Under the hood, constructing a point eagerly decodes the compressed bytes into
 * the library's internal ge_p3 and ge_cached representations. This costs a small
 * amount of extra memory per point but avoids repeated decompression every time you
 * do arithmetic, which is a big win when the same point appears in many operations
 * (ring signatures, bulletproofs, etc.).
 */
struct crypto_point_t final : SerializablePod<32>
{
    /**
     * Constructors -- all variants decode the input bytes and cache the internal
     * ge_p3 / ge_cached representations automatically. If the bytes do not represent
     * a valid curve point, construction will throw.
     */

    crypto_point_t();

    crypto_point_t(std::initializer_list<unsigned char> input);

    explicit crypto_point_t(const std::vector<unsigned char> &input);

    explicit crypto_point_t(const std::string &s);

    JSON_STRING_CONSTRUCTOR(crypto_point_t, fromJSON)

    explicit crypto_point_t(const char value[65]);

    explicit crypto_point_t(const ge_p3 &point);

    explicit crypto_point_t(const uint64_t &number);

    ~crypto_point_t();

    /**
     * Tests whether an arbitrary value can be decoded as a valid curve point.
     * @param value the raw bytes, hex string, or other convertible type to test
     * @return true if the value represents a valid Ed25519 point
     */
    template<typename T> static bool check(const T &value)
    {
        /**
         * Try loading the given value into a point type and then check to see if the bytes
         * that we have loaded are actually a point. If we fail at any point, then it
         * definitely is not a point that was provided.
         */
        try
        {
            const auto check_value = crypto_point_t(value);

            return check_value.check();
        }
        catch (const std::exception &e)
        {
            PRINTF(e.what())

            return false;
        }
    }

    /**
     * Constructs a point by interpreting a uint256_t as 32 compressed-point bytes.
     * @param number the 256-bit integer whose byte representation is the point encoding
     * @return the decoded curve point
     */
    static crypto_point_t from_uint256(const uint256_t &number);

    /**
     * Arithmetic operators -- these are Ed25519 group operations. Addition and subtraction
     * combine points on the curve (P + Q, P - Q). Unary negation returns -P, the point
     * whose y-coordinate is the same but x is negated (mod q).
     */

    crypto_point_t operator+(const crypto_point_t &other) const;

    void operator+=(const crypto_point_t &other);

    crypto_point_t operator-(const crypto_point_t &other) const;

    crypto_point_t operator-() const;

    void operator-=(const crypto_point_t &other);

    /**
     * Returns the ge_cached representation of this point, used internally by the ed25519
     * library for fast point addition.
     * @return the cached representation
     */
    [[nodiscard]] ge_cached cached() const;

    /**
     * Checks whether the stored bytes decode to a valid Ed25519 curve point.
     * @return true if this is a valid point on the curve
     */
    [[nodiscard]] bool check() const;

    /**
     * Checks that the point belongs to the prime-order subgroup (order l) of the Ed25519
     * curve. Because Ed25519 has cofactor 8, not every valid curve point is in the main
     * subgroup -- small-subgroup points can cause subtle security issues if not rejected.
     * @return true if the point is in the prime-order subgroup
     */
    [[nodiscard]] bool check_subgroup() const;

    /**
     * Checks if the point is empty (all zero bytes, i.e., uninitialized).
     * @return true if every byte is zero
     */
    [[nodiscard]] bool empty() const override;

    /**
     * Multiplies the point by the cofactor (8), projecting it into the prime-order subgroup.
     * This is the standard defense against small-subgroup attacks on Ed25519: if P has a
     * small-subgroup component, 8P zeros it out. Result = 8 * P.
     * @return the cofactor-cleared point
     */
    [[nodiscard]] crypto_point_t mul8() const;

    /**
     * Returns the additive inverse of this point (-P), such that P + (-P) = Z (identity).
     * @return the negated point
     */
    [[nodiscard]] crypto_point_t negate() const;

    /**
     * Returns the ge_p3 (extended coordinates) representation of this point. This is the
     * form most ed25519 low-level operations expect as input.
     * @return the ge_p3 representation
     */
    [[nodiscard]] ge_p3 p3() const;

    /**
     * Generates a random point by creating a random scalar and computing scalar * G.
     * @return a uniformly distributed point in the prime-order subgroup
     */
    [[nodiscard]] static crypto_point_t random();

    /**
     * Generates a vector of random points.
     * @param count how many random points to generate
     * @return vector of independently sampled random points
     */
    [[nodiscard]] static std::vector<crypto_point_t> random(size_t count);

    /**
     * Maps arbitrary 32 bytes to a curve point via hash-and-reduce. Unlike the constructor,
     * this does not require the input to already be a valid point encoding.
     * @param bytes the 32 raw bytes to reduce onto the curve
     * @return a valid curve point derived from the input bytes
     */
    [[nodiscard]] static crypto_point_t reduce(const unsigned char bytes[32]);

    /**
     * Returns the point's compressed encoding interpreted as a 256-bit unsigned integer.
     * @return the 32 point bytes as a uint256_t
     */
    [[nodiscard]] uint256_t to_uint256_t() const;

    /**
     * Returns whether the point is a valid curve point and (by default) not the identity element.
     * Useful for input validation -- you almost always want to reject identity in cryptographic contexts.
     * @param allow_identity if true, the identity point Z is considered valid
     * @return true if the point passes validation
     */
    [[nodiscard]] bool valid(bool allow_identity = false) const;

  private:
    void load_hook() override;

    ge_p3 point3 = {};
    ge_cached cached_point = {};
};

namespace Crypto
{
    /** Ed25519 base point (primary generator). Public keys are derived as P = sG. */
    const crypto_point_t G = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

    /**
     * Secondary generator, derived deterministically by hashing G to a curve point (Hp(G)).
     * Nobody knows the discrete log of H relative to G, which is exactly what makes Pedersen
     * commitments binding: C = vH + bG hides value v with blinding factor b.
     */
    const crypto_point_t H = {0xdd, 0x2a, 0xf5, 0xc2, 0x8a, 0xcc, 0xdc, 0x50, 0xc8, 0xbc, 0x4e,
                              0x15, 0x99, 0x12, 0x82, 0x3a, 0x87, 0x87, 0xc1, 0x18, 0x52, 0x97,
                              0x74, 0x5f, 0xb2, 0x30, 0xe2, 0x64, 0x6c, 0xd7, 0x7e, 0xf6};

    /** Tertiary generator for protocols requiring a third independent base point (e.g., Triptych signatures). */
    const crypto_point_t U = {0x3b, 0x51, 0x37, 0xf1, 0x67, 0x4c, 0x55, 0xf9, 0xad, 0x2b, 0x5d,
                              0xbf, 0x14, 0x99, 0x69, 0xc5, 0x62, 0x4a, 0x84, 0x36, 0xbc, 0xfb,
                              0x99, 0xc6, 0xac, 0x30, 0x1b, 0x4b, 0x31, 0x21, 0x93, 0xf2};

    /** Zero point (0,0) -- NOT a valid curve point. Used as a sentinel / empty / uninitialized value. */
    const crypto_point_t ZP = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    /** Identity element (0,1) of the Ed25519 group. P + Z = P for any point P. */
    const crypto_point_t Z = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
} // namespace Crypto

/** A public key -- the curve point P = sG derived from a secret scalar s. */
typedef crypto_point_t crypto_public_key_t;

/** A shared ECDH derivation point, typically computed as aB or bA between two parties. */
typedef crypto_point_t crypto_derivation_t;

/** A key image -- a unique, unlinkable tag derived from a secret key, used to detect double-spends in ring signatures. */
typedef crypto_point_t crypto_key_image_t;

/** A Pedersen commitment -- a hiding and binding commitment to a value, typically C = vH + bG. */
typedef crypto_point_t crypto_pedersen_commitment_t;

#endif
