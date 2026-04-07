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
 * @file scalar_t.h
 * @brief Ed25519 scalar type (integer modulo the group order l) with full arithmetic.
 *
 * Scalars are the "numbers" side of elliptic curve cryptography -- 32-byte integers
 * reduced modulo l (the prime order of the Ed25519 base-point subgroup). All arithmetic
 * (+, -, *, /) is performed mod l automatically. Scalars are used as secret keys, blinding
 * factors, challenge values, and anywhere you need a field element.
 */

#ifndef SCALAR_T_H
#define SCALAR_T_H

#include <types/point_t.h>

/** Validates that a value is a canonical scalar (may be zero). Throws std::invalid_argument if not. */
#ifndef SCALAR_OR_THROW
#include <stdexcept>
#define SCALAR_OR_THROW(value)                                                 \
    if (!(value).valid(true))                                                  \
    {                                                                          \
        throw std::invalid_argument(std::string(#value) + " is not a scalar"); \
    }
#endif
/** Validates that a value is a canonical non-zero scalar. Throws std::invalid_argument if zero or invalid. */
#ifndef SCALAR_NZ_OR_THROW
#include <stdexcept>
#define SCALAR_NZ_OR_THROW(value)                                              \
    if (!(value).valid())                                                      \
    {                                                                          \
        throw std::invalid_argument(std::string(#value) + " is not a scalar"); \
    }
#endif

/**
 * A 32-byte integer modulo l (the Ed25519 group order, ~2^252).
 *
 * All arithmetic operations automatically reduce results mod l, so you can write
 * mathematical expressions naturally (e.g., `a * b + c`) and get correct modular results.
 * Scalars also support multiplication with curve points (`scalar * point`) to perform
 * the fundamental scalar-point multiplication used everywhere in EC cryptography.
 *
 * Constructors copy raw bytes without canonicalization. Callers that need a canonical
 * value call `.reduce()` afterwards for pure mod-l reduction. The ONLY public path that
 * applies RFC 8032 §5.1.5 private-key clamping is `scalar_t::from_rfc8032_seed()`; it
 * must never be applied to random values, hash outputs, or Fiat-Shamir challenges.
 */
struct scalar_t final : SerializablePod<32>
{
    /**
     * Constructors -- accept hex strings, byte vectors, integers, or bit vectors.
     * Raw bytes are copied without reduction. Call `.reduce()` for canonical form, or
     * use `from_rfc8032_seed()` / `from_uniform_bytes()` when those semantics are needed.
     */

    scalar_t() = default;

    scalar_t(std::initializer_list<unsigned char> input);

    explicit scalar_t(const std::vector<unsigned char> &input);

    explicit scalar_t(const std::string &s);

    JSON_STRING_CONSTRUCTOR(scalar_t, fromJSON)

    explicit scalar_t(const char value[65]);

    explicit scalar_t(const uint64_t &number);

    explicit scalar_t(const std::vector<scalar_t> &bits);

    /**
     * Constructs a scalar from a uint256_t, always reducing modulo l since uint256_t
     * values in [l, 2^256) are possible.
     * @param number the 256-bit integer to interpret as scalar bytes
     * @return the resulting scalar, canonical in [0, l)
     */
    static scalar_t from_uint256(const uint256_t &number);

    /**
     * Constructs a scalar from a 32-byte buffer and reduces it mod l via pure
     * sc_reduce (no clamping). This is the fast in-place reduction path used
     * by the transcript hot path (hash_t::scalar()) to avoid intermediate vector
     * allocations. Fixed-width reference parameter prevents accidental pointer
     * slicing at the call site. Residual bias is ~2^-124 (statistically
     * undetectable, not lattice-exploitable).
     *
     * @param bytes_in 32-byte input (typically a hash output or raw scalar bytes)
     * @return the bytes reduced mod l
     */
    [[nodiscard]] static scalar_t from_bytes_reduced(const unsigned char (&bytes_in)[32]);

    /**
     * Constructs a scalar by applying RFC 8032 §5.1.5 private-key clamping
     * (clear low 3 bits of byte 0, clear bit 255, set bit 254) followed by
     * reduction mod l. THIS IS THE ONLY PUBLIC CLAMP ENTRY POINT in the library.
     * Use exclusively for Ed25519 secret-key expansion per RFC 8032 §5.1.5.
     * Applying clamping to random values, hash outputs, or Fiat-Shamir challenges
     * produces lattice-attackable biased Schnorr/ECDSA nonces and must never be
     * done outside of RFC 8032 private-key derivation.
     *
     * @param seed pointer to a 32-byte Ed25519 seed (lower half of SHA-512(private_key))
     * @return the clamped-then-reduced signing scalar
     */
    [[nodiscard]] static scalar_t from_rfc8032_seed(const unsigned char *seed);

    /**
     * Constructs a scalar by unbiased wide reduction of a 64-byte buffer (typically
     * SHA-512 output, HMAC-SHA-512 output, or 64 bytes of CSPRNG entropy). Uses the
     * three-limb split (a + b*2^168 + c*2^336) from reduce_wide_hash() to eliminate
     * the ~2^-124 statistical bias of naive 32-byte modular reduction. This is the
     * uniform-sampling path; use it for random scalars, nonces, blindings, and any
     * value whose distribution must be statistically indistinguishable from uniform
     * on [0, l).
     *
     * @param buf 64-byte input (SHA-512 digest, HMAC output, or CSPRNG entropy)
     * @return the unbiased reduced scalar
     */
    [[nodiscard]] static scalar_t from_uniform_bytes(const unsigned char (&buf)[64]);

    /**
     * Comparison and arithmetic operators. All arithmetic (+, -, *, /) is mod l.
     * Division is implemented as multiplication by the modular inverse.
     */

    bool operator==(const scalar_t &other) const;

    bool operator==(const uint64_t &other) const;

    bool operator==(const uint256_t &other) const;

    bool operator!=(const scalar_t &other) const;

    bool operator!=(const uint64_t &other) const;

    bool operator!=(const uint256_t &other) const;

    bool operator<(const scalar_t &other) const;

    bool operator<(const uint64_t &other) const;

    bool operator<(const uint256_t &other) const;

    bool operator<=(const uint64_t &other) const;

    bool operator<=(const uint256_t &other) const;

    bool operator>(const scalar_t &other) const;

    bool operator>(const uint64_t &other) const;

    bool operator>(const uint256_t &other) const;

    bool operator>=(const uint64_t &other) const;

    bool operator>=(const uint256_t &other) const;

    scalar_t operator+(const scalar_t &other) const;

    scalar_t operator+(const uint64_t &other) const;

    scalar_t operator+(const uint256_t &other) const;

    void operator+=(const scalar_t &other);

    void operator+=(const uint64_t &other);

    void operator+=(const uint256_t &other);

    scalar_t operator-(const scalar_t &other) const;

    scalar_t operator-(const uint64_t &other) const;

    scalar_t operator-(const uint256_t &other) const;

    void operator-=(const scalar_t &other);

    void operator-=(const uint64_t &other);

    void operator-=(const uint256_t &other);

    scalar_t operator*(const scalar_t &other) const;

    scalar_t operator*(const uint64_t &other) const;

    scalar_t operator*(const uint256_t &other) const;

    void operator*=(const scalar_t &other);

    void operator*=(const uint64_t &other);

    void operator*=(const uint256_t &other);

    scalar_t operator/(const scalar_t &other) const;

    scalar_t operator/(const uint64_t &other) const;

    scalar_t operator/(const uint256_t &other) const;

    void operator/=(const scalar_t &other);

    void operator/=(const uint64_t &other);

    void operator/=(const uint256_t &other);

    /**
     * Scalar-point multiplication: computes s * P on the Ed25519 curve. This is the core
     * operation behind public key derivation (s * G), Pedersen commitments, and more.
     * @param point the curve point to multiply
     * @return the resulting curve point
     */
    point_t operator*(const point_t &point) const;

    /**
     * Double scalar multiplication: computes this*A + b*B in a single operation, which is
     * significantly faster than computing each product separately and adding. This pattern
     * appears constantly in signature verification (e.g., checking sG = R + eP).
     * @param A first point
     * @param b second scalar
     * @param B second point
     * @return the combined result this*A + b*B
     */
    [[nodiscard]] point_t dbl_mult(const point_t &A, const scalar_t &b, const point_t &B) const;

    /**
     * Tests whether an arbitrary value represents a valid canonical scalar (i.e., in [0, l)).
     * @param value the raw bytes, hex string, or other convertible type to test
     * @return true if the value is a valid scalar
     */
    template<typename T> static bool check(const T &value)
    {
        /**
         * Try loading the given value into a scalar type without performing a scalar reduction
         * (which would defeat the purpose of this check) and then check to see if the bytes
         * that we have loaded indicate that the value is actually a scalar. If we fail
         * at any point, then it definitely is not a scalar that was provided.
         */
        try
        {
            scalar_t check_value(value);

            return check_value.check();
        }
        catch (...)
        {
            return false;
        }
    }

    /**
     * Checks whether the stored bytes represent a canonical scalar (in the range [0, l)).
     * @return true if the value is a valid reduced scalar
     */
    [[nodiscard]] bool check() const;

    /**
     * Computes the modular inverse (1/x mod l). Multiplying a scalar by its inverse gives ONE.
     * Used for scalar division and in many proof protocols that need to "undo" a multiplication.
     * @return the multiplicative inverse of this scalar
     */
    [[nodiscard]] scalar_t invert() const;

    /**
     * Checks whether the scalar is non-zero. Returns true if the scalar has any non-zero byte.
     * @return true if the scalar is not zero
     */
    [[nodiscard]] bool is_nonzero() const;

    /**
     * Returns the additive inverse (-x mod l), such that x + (-x) = 0 mod l.
     * @return the negated scalar
     */
    [[nodiscard]] scalar_t negate() const;

    /**
     * Computes s * G (scalar times the base point), giving the corresponding public key point.
     * This is the fundamental public-key derivation operation in Ed25519.
     * @return the curve point s * G
     */
    [[nodiscard]] point_t point() const;

    /**
     * Modular exponentiation: r = s^e mod l.
     * @param exponent the scalar exponent
     * @return s raised to the power e, mod l
     */
    [[nodiscard]] scalar_t pow(const scalar_t &exponent) const;

    /**
     * Modular exponentiation: r = s^e mod l (integer exponent variant).
     * @param exponent the integer exponent
     * @return s raised to the power e, mod l
     */
    [[nodiscard]] scalar_t pow(size_t exponent) const;

    /**
     * Expands this scalar into a vector of its consecutive powers: [s^0, s^1, s^2, ..., s^(count-1)].
     * Uses O(n) running multiplication rather than independent pow() calls. Heavily used in
     * bulletproofs for challenge-power vectors.
     * @param count how many powers to generate
     * @param descending if true, returns [s^(count-1), ..., s^1, s^0]
     * @param include_zero if true (default), the first element is s^0 = 1; if false, starts at s^1
     * @return vector of scalar powers
     */
    [[nodiscard]] std::vector<scalar_t>
        pow_expand(size_t count, bool descending = false, bool include_zero = true) const;

    /**
     * Modular exponentiation with an additional integer modulus: r = (s^e) mod l, then
     * the integer result mod m. Useful when you need power-of-scalar values in a cyclic
     * index space.
     * @param exponent the scalar exponent
     * @param modulus the integer modulus applied after exponentiation
     * @return (s^e mod l) mod m
     */
    [[nodiscard]] scalar_t powm(const scalar_t &exponent, size_t modulus) const;

    /**
     * Computes the sum of powers: s^0 + s^1 + s^2 + ... + s^(count-1). This is the geometric
     * series sum, useful in bulletproofs verification equations.
     * @param count how many power terms to sum
     * @return the sum of the first `count` powers of this scalar
     */
    [[nodiscard]] scalar_t pow_sum(size_t count) const;

    /**
     * Generates a cryptographically random scalar uniformly distributed on [0, l).
     *
     * Samples 64 bytes of CSPRNG entropy and applies the unbiased wide-reduction path
     * (`reduce_wide_hash`) to produce a scalar whose distribution is statistically
     * indistinguishable from uniform on [0, l).
     *
     * @return a cryptographically random scalar with unbiased distribution on [0, l)
     */
    [[nodiscard]] static scalar_t random();

    /**
     * Generates a vector of cryptographically random scalars.
     * @param count how many random scalars to generate
     * @return vector of independently sampled random scalars
     */
    [[nodiscard]] static std::vector<scalar_t> random(size_t count);

    /**
     * Returns the scalar reduced to the canonical range [0, l) via pure modular
     * reduction (sc_reduce). If the scalar is already canonical, this is a no-op.
     * Useful after constructing from raw bytes that might exceed the group order.
     * Performs ONLY modular reduction, not RFC 8032 clamping — the only path that
     * applies clamping is `from_rfc8032_seed()`.
     *
     * @return the scalar reduced mod l (pure, unclamped)
     */
    [[nodiscard]] scalar_t reduce() const;

    /**
     * Squares the scalar: r = s^2 mod l. Slightly more efficient than `pow(2)`.
     * @return s squared mod l
     */
    [[nodiscard]] scalar_t squared() const;

    /**
     * Decomposes the scalar into individual bits, returned as a vector of scalars (each 0 or 1).
     * Used in range proofs where you need to prove properties about individual bits of a value.
     * @param bits how many bits to extract (default 256, the full scalar width)
     * @return vector of single-bit scalars, LSB first
     */
    [[nodiscard]] std::vector<scalar_t> to_bits(size_t bits = 256) const;

    /**
     * Interprets the first 8 bytes of the scalar as a little-endian uint64_t. Useful for
     * extracting small numeric values that were encoded as scalars.
     * @return the low 64 bits of the scalar
     */
    [[nodiscard]] uint64_t to_uint64_t() const;

    /**
     * Returns the full scalar as a uint256_t for big-integer operations outside mod-l arithmetic.
     * @return the 256-bit integer representation
     */
    [[nodiscard]] uint256_t to_uint256_t() const;

    /**
     * Returns whether the scalar is canonical (in [0, l)) and, by default, non-zero.
     * Most cryptographic operations require non-zero scalars; pass allow_zero=true when zero is acceptable.
     * @param allow_zero if true, zero is considered valid
     * @return true if the scalar passes validation
     */
    [[nodiscard]] bool valid(bool allow_zero = false) const;

  private:
    void do_reduce();

    /**
     * Loads the scalar from a vector of individual bits
     * @param bits
     */
    void from_bits(const std::vector<scalar_t> &bits);
};

namespace Crypto
{
    /** Commonly used scalar constants. */
    const scalar_t ZERO = {0}; ///< The zero scalar (additive identity)
    const scalar_t ONE(1); ///< The one scalar (multiplicative identity)
    const scalar_t TWO(2); ///< Two -- handy for doubling operations
    const scalar_t EIGHT(8); ///< The cofactor of Ed25519 (h = 8), used for cofactor clearing
    const scalar_t INV_EIGHT =
        EIGHT.invert(); ///< 1/8 mod l -- multiplied into proof elements so verifiers can clear the cofactor with a
                        ///< cheap multiply-by-8 instead of a full scalar mult

    /**
     * l = 2^252 + 27742317777372353535851937790883648493
     *
     * The prime order of the Ed25519 base-point subgroup. All scalar arithmetic is mod l.
     */
    const scalar_t l = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
    /**
     * q = 2^255 - 19
     *
     * The prime defining the Ed25519 base field (coordinate arithmetic is mod q).
     * Provided here for reference; most code works with the group order l instead.
     */
    const scalar_t q = {0xeD, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
} // namespace Crypto

/** A blinding factor used in Pedersen commitments (C = vH + bG) to hide the committed value. */
typedef scalar_t blinding_factor_t;

#endif
