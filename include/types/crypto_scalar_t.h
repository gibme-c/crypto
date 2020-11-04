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

#ifndef CRYPTO_SCALAR_T
#define CRYPTO_SCALAR_T

#include <types/crypto_point_t.h>

#ifndef SCALAR_OR_THROW
#include <stdexcept>
#define SCALAR_OR_THROW(value)                                                 \
    if (!(value).valid(true))                                                  \
    {                                                                          \
        throw std::invalid_argument(std::string(#value) + " is not a scalar"); \
    }
#endif
#ifndef SCALAR_NZ_OR_THROW
#include <stdexcept>
#define SCALAR_NZ_OR_THROW(value)                                              \
    if (!(value).valid())                                                      \
    {                                                                          \
        throw std::invalid_argument(std::string(#value) + " is not a scalar"); \
    }
#endif

struct crypto_scalar_t final : SerializablePod<32>
{
    /**
     * Constructor methods
     */

    crypto_scalar_t() = default;

    crypto_scalar_t(std::initializer_list<unsigned char> input, bool reduce = false);

    explicit crypto_scalar_t(const std::vector<unsigned char> &input, bool reduce = false);

    explicit crypto_scalar_t(const std::string &s, bool reduce = false);

    JSON_STRING_CONSTRUCTOR(crypto_scalar_t, fromJSON)

    explicit crypto_scalar_t(const char value[65], bool reduce = false);

    explicit crypto_scalar_t(const uint64_t &number, bool reduce = false);

    explicit crypto_scalar_t(const std::vector<crypto_scalar_t> &bits, bool reduce = false);

    /**
     * Constructs a scalar from a uint256_t
     * @param number
     * @param reduce
     * @return
     */
    static crypto_scalar_t from_uint256(const uint256_t &number, bool reduce = false);

    /**
     * Operator overloads to make arithmetic a lot easier to handle in methods that use these structures
     */

    bool operator==(const crypto_scalar_t &other) const;

    bool operator==(const uint64_t &other) const;

    bool operator==(const uint256_t &other) const;

    bool operator!=(const crypto_scalar_t &other) const;

    bool operator!=(const uint64_t &other) const;

    bool operator!=(const uint256_t &other) const;

    bool operator<(const crypto_scalar_t &other) const;

    bool operator<(const uint64_t &other) const;

    bool operator<(const uint256_t &other) const;

    bool operator<=(const uint64_t &other) const;

    bool operator<=(const uint256_t &other) const;

    bool operator>(const crypto_scalar_t &other) const;

    bool operator>(const uint64_t &other) const;

    bool operator>(const uint256_t &other) const;

    bool operator>=(const uint64_t &other) const;

    bool operator>=(const uint256_t &other) const;

    crypto_scalar_t operator+(const crypto_scalar_t &other) const;

    crypto_scalar_t operator+(const uint64_t &other) const;

    crypto_scalar_t operator+(const uint256_t &other) const;

    void operator+=(const crypto_scalar_t &other);

    void operator+=(const uint64_t &other);

    void operator+=(const uint256_t &other);

    crypto_scalar_t operator-(const crypto_scalar_t &other) const;

    crypto_scalar_t operator-(const uint64_t &other) const;

    crypto_scalar_t operator-(const uint256_t &other) const;

    void operator-=(const crypto_scalar_t &other);

    void operator-=(const uint64_t &other);

    void operator-=(const uint256_t &other);

    crypto_scalar_t operator*(const crypto_scalar_t &other) const;

    crypto_scalar_t operator*(const uint64_t &other) const;

    crypto_scalar_t operator*(const uint256_t &other) const;

    void operator*=(const crypto_scalar_t &other);

    void operator*=(const uint64_t &other);

    void operator*=(const uint256_t &other);

    crypto_scalar_t operator/(const crypto_scalar_t &other) const;

    crypto_scalar_t operator/(const uint64_t &other) const;

    crypto_scalar_t operator/(const uint256_t &other) const;

    void operator/=(const crypto_scalar_t &other);

    void operator/=(const uint64_t &other);

    void operator/=(const uint256_t &other);

    /**
     * Overloads a Scalar * Point returning the resulting point
     * @param point
     * @return
     */
    crypto_point_t operator*(const crypto_point_t &point) const;

    /**
     * Performs a double scalar mult operation which is slightly faster than
     * two single scalarmult operations added together
     * @param A
     * @param b
     * @param B
     * @return
     */
    [[nodiscard]] crypto_point_t
        dbl_mult(const crypto_point_t &A, const crypto_scalar_t &b, const crypto_point_t &B) const;

    /**
     * Allows us to check a random value to determine if it is a scalar or not
     * @param value
     * @return
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
            crypto_scalar_t check_value(value, false);

            return check_value.check();
        }
        catch (const std::exception &e)
        {
            PRINTF(e.what())

            return false;
        }
    }

    /**
     * Member methods used in general operations using scalars
     */

    /**
     * Checks to validate that the scalar is indeed a scalar
     * @return
     */
    [[nodiscard]] bool check() const;

    /**
     * Provides the inversion of the scalar (1/x)
     * @return
     */
    [[nodiscard]] crypto_scalar_t invert() const;

    /**
     * Checks to validate that the scalar is NOT zero (0)
     * @return
     */
    [[nodiscard]] bool is_nonzero() const;

    /**
     * Returns the negation of the scalar (-x)
     * @return
     */
    [[nodiscard]] crypto_scalar_t negate() const;

    /**
     * Returns the curve point for this scalar
     *
     * @return
     */
    [[nodiscard]] crypto_point_t point() const;

    /**
     * Raises the scalar to the specified power
     * r = (s ^ e)
     * @param exponent
     * @return
     */
    [[nodiscard]] crypto_scalar_t pow(const crypto_scalar_t &exponent) const;

    /**
     * Raises the scalar to the specified power
     * r = (s ^ e)
     * @param exponent
     * @return
     */
    [[nodiscard]] crypto_scalar_t pow(size_t exponent) const;

    /**
     * Generates a vector of powers of the scalar
     * @param count
     * @param descending
     * @return
     */
    [[nodiscard]] std::vector<crypto_scalar_t>
        pow_expand(size_t count, bool descending = false, bool include_zero = true) const;

    /**
     * Raises the scalar to the specified power with a modulus
     * r = (s ^ e) % m
     * @param exponent
     * @param modulus
     * @return
     */
    [[nodiscard]] crypto_scalar_t powm(const crypto_scalar_t &exponent, size_t modulus) const;

    /**
     * Sums the specified power of the scalar
     * @param count
     * @return
     */
    [[nodiscard]] crypto_scalar_t pow_sum(size_t count) const;

    /**
     * Generates a random scalar
     *
     * @return
     */
    [[nodiscard]] static crypto_scalar_t random();

    /**
     * Generates a vector of random scalars
     *
     * @param count
     * @return
     */
    [[nodiscard]] static std::vector<crypto_scalar_t> random(size_t count);

    /**
     * Returns the reduced form of the scalar (if not already reduced)
     */
    [[nodiscard]] crypto_scalar_t reduce() const;

    /**
     * Squares the scalar
     * r = (s ^ 2)
     * @return
     */
    [[nodiscard]] crypto_scalar_t squared() const;

    /**
     * Converts the scalar to a vector of scalars that represent the individual
     * bits of the scalar (maximum of 256 bits as 32 * 8 = 256)
     * @param bits
     * @return
     */
    [[nodiscard]] std::vector<crypto_scalar_t> to_bits(size_t bits = 256) const;

    /**
     * Encodes the first 8 bytes of the scalar as a uint64_t
     * @return
     */
    [[nodiscard]] uint64_t to_uint64_t() const;

    /**
     * Returns the scalar as an uint256_t
     * @return
     */
    [[nodiscard]] uint256_t to_uint256_t() const;

    /**
     * Returns if the scalar is a valid scalar AND non-zero (unless allow_zero is set)
     * @param allow_zero
     * @return
     */
    [[nodiscard]] bool valid(bool allow_zero = false) const;

  private:
    void do_reduce();

    /**
     * Loads the scalar from a vector of individual bits
     * @param bits
     */
    void from_bits(const std::vector<crypto_scalar_t> &bits);
};

namespace Crypto
{
    // Commonly used Scalar values (0, 1, 2, 8, 1/8)
    const crypto_scalar_t ZERO = {0}, ONE(1), TWO(2), EIGHT(8), INV_EIGHT = EIGHT.invert();

    /**
     * l = 2^252 + 27742317777372353535851937790883648493
     */
    const crypto_scalar_t l = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                               0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
    /**
     * q = 2^255 - 19
     * Value is provided here for reference purposes
     */
    const crypto_scalar_t q = {0xeD, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
} // namespace Crypto

typedef crypto_scalar_t crypto_blinding_factor_t;

#endif
