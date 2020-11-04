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

#ifndef CRYPTO_POINT_T
#define CRYPTO_POINT_T

#include <ed25519.h>
#include <helpers/debug_helper.h>
#include <serialization.h>

struct crypto_point_t final : SerializablePod<32>
{
    /**
     * Various constructor methods for creating a point. All of the methods
     * will load the various types, then automatically load the related
     * ge_p2 and ge_p2 points into cached memory to help speed up operations
     * that use them later without incurring the cost of loading them from bytes
     * again. While this uses a bit more memory to represent a point, it does
     * provide us with a more performant experience when conducting arithmetic
     * operations using the point
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
     * Allows us to check a random value to determine if it is a point or not
     * @param value
     * @return
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
     * Constructs a point from a uint256_t
     * @param number
     * @return
     */
    static crypto_point_t from_uint256(const uint256_t &number);

    /**
     * Overloading a bunch of the standard operators to make operations using this
     * structure to use a lot cleaner syntactic sugar in downstream code.
     */

    crypto_point_t operator+(const crypto_point_t &other) const;

    void operator+=(const crypto_point_t &other);

    crypto_point_t operator-(const crypto_point_t &other) const;

    crypto_point_t operator-() const;

    void operator-=(const crypto_point_t &other);

    /**
     * Member methods used in general operations using scalars
     */

    /**
     * Returns a pointer to a ge_cached representation of the point
     * @return
     */
    [[nodiscard]] ge_cached cached() const;

    /**
     * Checks to confirm that the point is indeed a point
     * @return
     */
    [[nodiscard]] bool check() const;

    /**
     * Checks to confirm that the point is in our subgroup
     * @return
     */
    [[nodiscard]] bool check_subgroup() const;

    /**
     * Checks if the value is empty
     * @return
     */
    [[nodiscard]] bool empty() const override;

    /**
     * Computes 8P
     * @return
     */
    [[nodiscard]] crypto_point_t mul8() const;

    /**
     * Returns the negation of the point
     * @return
     */
    [[nodiscard]] crypto_point_t negate() const;

    /**
     * Returns a pointer to a ge_p3 representation of the point
     * @return
     */
    [[nodiscard]] ge_p3 p3() const;

    /**
     * Generates a random point
     *
     * @return
     */
    [[nodiscard]] static crypto_point_t random();

    /**
     * Generates a vector of random points
     *
     * @param count
     * @return
     */
    [[nodiscard]] static std::vector<crypto_point_t> random(size_t count);

    /**
     * Reduces the given bytes, whether a point on the curve or not, to a point
     * @param bytes
     * @return
     */
    [[nodiscard]] static crypto_point_t reduce(const unsigned char bytes[32]);

    /**
     * Returns the point as an uint256_t
     * @return
     */
    [[nodiscard]] uint256_t to_uint256_t() const;

    /**
     * Returns if the point is a valid point on the curve AND non-identity (unless allow_identity is set)
     * @param allow_identity
     * @return
     */
    [[nodiscard]] bool valid(bool allow_identity = false) const;

  private:
    void load_hook() override;

    ge_p3 point3;
    ge_cached cached_point;
};

namespace Crypto
{
    // Primary Generator Point (x,-4/5)
    const crypto_point_t G = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                              0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

    // Secondary Generator Point = Hp(G)
    const crypto_point_t H = {0xdd, 0x2a, 0xf5, 0xc2, 0x8a, 0xcc, 0xdc, 0x50, 0xc8, 0xbc, 0x4e,
                              0x15, 0x99, 0x12, 0x82, 0x3a, 0x87, 0x87, 0xc1, 0x18, 0x52, 0x97,
                              0x74, 0x5f, 0xb2, 0x30, 0xe2, 0x64, 0x6c, 0xd7, 0x7e, 0xf6};

    const crypto_point_t U = {0x3b, 0x51, 0x37, 0xf1, 0x67, 0x4c, 0x55, 0xf9, 0xad, 0x2b, 0x5d,
                              0xbf, 0x14, 0x99, 0x69, 0xc5, 0x62, 0x4a, 0x84, 0x36, 0xbc, 0xfb,
                              0x99, 0xc6, 0xac, 0x30, 0x1b, 0x4b, 0x31, 0x21, 0x93, 0xf2};

    // Zero Point (0,0)
    const crypto_point_t ZP = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Neutral Point (0,1)
    const crypto_point_t Z = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
} // namespace Crypto

typedef crypto_point_t crypto_public_key_t;

typedef crypto_point_t crypto_derivation_t;

typedef crypto_point_t crypto_key_image_t;

typedef crypto_point_t crypto_pedersen_commitment_t;

#endif
