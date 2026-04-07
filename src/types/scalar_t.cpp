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
 * @file scalar_t.cpp
 * @brief Ed25519 scalar arithmetic mod l with RFC-8032 clamping.
 */

#include <core/crypto_config.h>
#include <ed25519/include/ed25519_secure_erase.h>
#include <helpers/constant_time.h>
#include <randompp.hpp>
#include <tinysha.h>
#include <types/scalar_t.h>

scalar_t::scalar_t(std::initializer_list<unsigned char> input, bool reduce)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));

    if (reduce)
    {
        do_reduce();
    }
}

scalar_t::scalar_t(const std::vector<unsigned char> &input, bool reduce)
{
    /**
     * We allow loading a full scalar (256-bits), a uint64_t (64-bits), or a uint32_t (32-bits)
     */
    if (input.size() != sizeof(bytes) && input.size() != 8 && input.size() != 4)
    {
        throw std::runtime_error("Could not load scalar");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));

    if (reduce)
    {
        do_reduce();
    }
}

scalar_t::scalar_t(const std::string &s, bool reduce)
{
    from_string(s);

    if (reduce)
    {
        do_reduce();
    }
}

scalar_t::scalar_t(const uint64_t &number, bool reduce)
{
    std::memcpy(bytes, &number, sizeof(number));

    if (reduce)
    {
        do_reduce();
    }
}

scalar_t::scalar_t(const char *value, bool reduce)
{
    const auto str = std::string(value);

    from_string(str);

    if (reduce)
    {
        do_reduce();
    }
}

scalar_t::scalar_t(const std::vector<scalar_t> &bits, bool reduce)
{
    from_bits(bits);

    if (reduce)
    {
        do_reduce();
    }
}

scalar_t scalar_t::from_uint256(const uint256_t &number, bool reduce)
{
    unsigned char bytes[32];

    std::memcpy(bytes, &number, sizeof(number));

    auto result = scalar_t(std::vector<unsigned char>(std::begin(bytes), std::end(bytes)));

    if (reduce)
    {
        return result.reduce();
    }

    return result;
}

bool scalar_t::operator==(const scalar_t &other) const
{
    return constant_time_equals(bytes, other.bytes, sizeof(bytes));
}

bool scalar_t::operator==(const uint64_t &other) const
{
    const auto other_scalar = scalar_t(other);

    return (*this == other_scalar);
}

bool scalar_t::operator==(const uint256_t &other) const
{
    const auto other_scalar = scalar_t::from_uint256(other);

    return (*this == other_scalar);
}

bool scalar_t::operator!=(const scalar_t &other) const
{
    return !(*this == other);
}

bool scalar_t::operator!=(const uint64_t &other) const
{
    return !(*this == other);
}

bool scalar_t::operator!=(const uint256_t &other) const
{
    return !(*this == other);
}

// NOTE: These comparison operators are variable-time. Do NOT use on secret
// scalar values (private keys, nonces, blinding factors).
bool scalar_t::operator<(const scalar_t &other) const
{
    for (size_t i = sizeof(bytes); i-- > 0;)
    {
        if (bytes[i] < other.bytes[i])
        {
            return true;
        }

        if (bytes[i] > other.bytes[i])
        {
            return false;
        }
    }

    return false;
}

bool scalar_t::operator<(const uint64_t &other) const
{
    const auto other_scalar = scalar_t(other);

    return (*this < other_scalar);
}

bool scalar_t::operator<(const uint256_t &other) const
{
    const auto other_scalar = scalar_t::from_uint256(other);

    return (*this < other_scalar);
}

bool scalar_t::operator<=(const uint64_t &other) const
{
    return (*this < other) || (*this == other);
}

bool scalar_t::operator<=(const uint256_t &other) const
{
    return (*this < other) || (*this == other);
}

bool scalar_t::operator>(const scalar_t &other) const
{
    for (size_t i = sizeof(bytes); i-- > 0;)
    {
        if (bytes[i] > other.bytes[i])
        {
            return true;
        }

        if (bytes[i] < other.bytes[i])
        {
            return false;
        }
    }

    return false;
}

bool scalar_t::operator>(const uint64_t &other) const
{
    const auto other_scalar = scalar_t(other);

    return (*this > other_scalar);
}

bool scalar_t::operator>(const uint256_t &other) const
{
    const auto other_scalar = scalar_t::from_uint256(other);

    return (*this > other_scalar);
}

bool scalar_t::operator>=(const uint64_t &other) const
{
    return (*this > other) || (*this == other);
}

bool scalar_t::operator>=(const uint256_t &other) const
{
    return (*this > other) || (*this == other);
}

scalar_t scalar_t::operator+(const scalar_t &other) const
{
    scalar_t result;

    sc_add(result.bytes, bytes, other.bytes);

    return result;
}

scalar_t scalar_t::operator+(const uint64_t &other) const
{
    const auto other_scalar = scalar_t(other);

    return (*this + other_scalar);
}

scalar_t scalar_t::operator+(const uint256_t &other) const
{
    const auto other_scalar = scalar_t::from_uint256(other);

    return (*this + other_scalar);
}

void scalar_t::operator+=(const scalar_t &other)
{
    sc_add(bytes, bytes, other.bytes);
}

void scalar_t::operator+=(const uint64_t &other)
{
    const auto other_scalar = scalar_t(other);

    *this += other_scalar;
}

void scalar_t::operator+=(const uint256_t &other)
{
    const auto other_scalar = scalar_t::from_uint256(other);

    *this += other_scalar;
}

scalar_t scalar_t::operator-(const scalar_t &other) const
{
    scalar_t result;

    sc_sub(result.bytes, bytes, other.bytes);

    return result;
}

scalar_t scalar_t::operator-(const uint64_t &other) const
{
    const auto other_scalar = scalar_t(other);

    return (*this - other_scalar);
}

scalar_t scalar_t::operator-(const uint256_t &other) const
{
    const auto other_scalar = scalar_t::from_uint256(other);

    return (*this - other_scalar);
}

void scalar_t::operator-=(const scalar_t &other)
{
    sc_sub(bytes, bytes, other.bytes);
}

void scalar_t::operator-=(const uint64_t &other)
{
    const auto other_scalar = scalar_t(other);

    *this -= other_scalar;
}

void scalar_t::operator-=(const uint256_t &other)
{
    const auto other_scalar = scalar_t::from_uint256(other);

    *this -= other_scalar;
}

scalar_t scalar_t::operator*(const scalar_t &other) const
{
    scalar_t result;

    sc_mul(result.bytes, bytes, other.bytes);

    return result;
}

scalar_t scalar_t::operator*(const uint64_t &other) const
{
    const auto other_scalar = scalar_t(other);

    return (*this * other_scalar);
}

scalar_t scalar_t::operator*(const uint256_t &other) const
{
    const auto other_scalar = scalar_t::from_uint256(other);

    return (*this * other_scalar);
}

void scalar_t::operator*=(const scalar_t &other)
{
    sc_mul(bytes, bytes, other.bytes);
}

void scalar_t::operator*=(const uint64_t &other)
{
    const auto other_scalar = scalar_t(other);

    *this *= other_scalar;
}

void scalar_t::operator*=(const uint256_t &other)
{
    const auto other_scalar = scalar_t::from_uint256(other);

    *this *= other_scalar;
}

scalar_t scalar_t::operator/(const scalar_t &other) const
{
    // Division as multiplication by modular inverse: a/b = a * b^(-1) mod l
    return *this * other.invert();
}

scalar_t scalar_t::operator/(const uint64_t &other) const
{
    const auto other_scalar = scalar_t(other);

    return (*this / other_scalar);
}

scalar_t scalar_t::operator/(const uint256_t &other) const
{
    const auto other_scalar = scalar_t::from_uint256(other);

    return (*this / other_scalar);
}

void scalar_t::operator/=(const scalar_t &other)
{
    *this = *this / other;
}

void scalar_t::operator/=(const uint64_t &other)
{
    const auto other_scalar = scalar_t(other);

    *this /= other_scalar;
}

void scalar_t::operator/=(const uint256_t &other)
{
    const auto other_scalar = scalar_t::from_uint256(other);

    *this /= other_scalar;
}

point_t scalar_t::operator*(const point_t &point) const
{
    ge_p3 temp_p3 = {};

    ge_p1p1 temp_p1p1 = {};

    if (point == Crypto::G) // Use precomputed basepoint table for G — significantly faster
    {
        ge_scalarmult_base_ct(&temp_p1p1, bytes);

        ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

        return point_t(temp_p3);
    }
    else
    {
        const auto p = point.p3();

        // Constant-time scalar multiplication for arbitrary points
        ge_scalarmult_ct(&temp_p1p1, bytes, &p);

        ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

        return point_t(temp_p3);
    }
}

point_t scalar_t::dbl_mult(const point_t &A, const scalar_t &b, const point_t &B) const
{
    // Computes this*A + b*B using Straus' method (variable-time)
    ge_p1p1 temp_p1p1 = {};

    ge_p3 temp_p3 = {};

    if (B == Crypto::G)
    {
        temp_p3 = A.p3();

        ge_double_scalarmult_base_negate_vartime(&temp_p1p1, bytes, &temp_p3, b.data());
    }
    else
    {
        temp_p3 = B.p3();

        ge_dsmp temp_precomp;

        ge_dsm_precomp(temp_precomp, &temp_p3);

        temp_p3 = A.p3();

        ge_double_scalarmult_negate_vartime(&temp_p1p1, bytes, &temp_p3, b.data(), temp_precomp);
    }

    ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

    point_t point(temp_p3);

    // Map the "alternative" identity encoding ZP to the canonical identity Z
    if (point != Crypto::ZP)
    {
        return point;
    }

    return Crypto::Z;
}

bool scalar_t::check() const
{
    return sc_check_reduced(bytes) == 0;
}

scalar_t scalar_t::invert() const
{
    // Fermat's little theorem: x^(-1) = x^(l-2) mod l, where l is the Ed25519 group order
    return pow({0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10});
}

bool scalar_t::is_nonzero() const
{
    return sc_isnonzero(bytes) != 0;
}

scalar_t scalar_t::negate() const
{
    // -x mod l = (0 - x) mod l
    scalar_t zero({0});

    return zero - *this;
}

point_t scalar_t::point() const
{
    return *this * Crypto::G;
}

scalar_t scalar_t::pow(const scalar_t &exponent) const
{
    // convert our exponent to a vector of 256 individual bits
    const auto bits = exponent.to_bits(256);

    scalar_t result(1), m(this->serialize());

    // SECURITY: constant-time double-and-multiply. Always iterate all 256 bits
    // and always perform the multiply, selecting between the real product and
    // the previous result via constant-time conditional copy. This prevents
    // leaking exponent bits through timing.
    for (size_t i = 0; i < 256; ++i)
    {
        // Always compute the product (constant work per iteration)
        const auto product = result * m;

        // Constant-time select: if bit is 1, use product; otherwise keep result.
        // bits[i][0] is 0 or 1. We build a mask: 0x00 if 0, 0xFF if 1.
        const unsigned char bit = bits[i][0] & 1;
        const unsigned char mask = static_cast<unsigned char>(-static_cast<signed char>(bit));

        for (size_t j = 0; j < sizeof(result.bytes); ++j)
        {
            result.bytes[j] = (product.bytes[j] & mask) | (result.bytes[j] & ~mask);
        }

        m *= m;
    }

    return result;
}

scalar_t scalar_t::pow(size_t exponent) const
{
    return pow(scalar_t(exponent));
}

scalar_t scalar_t::powm(const scalar_t &exponent, size_t modulus) const
{
    return scalar_t(pow(exponent).to_uint256_t() % modulus);
}

std::vector<scalar_t> scalar_t::pow_expand(size_t count, bool descending, bool include_zero) const
{
    if (count == 0)
    {
        throw std::invalid_argument("count should be non-zero");
    }

    std::vector<scalar_t> result(count);

    // O(n) running product instead of O(n log n) independent pow(i) calls
    if (include_zero)
    {
        result[0] = scalar_t(1); // x^0 = 1

        for (size_t i = 1; i < count; ++i)
        {
            result[i] = result[i - 1] * (*this);
        }
    }
    else
    {
        result[0] = *this; // x^1

        for (size_t i = 1; i < count; ++i)
        {
            result[i] = result[i - 1] * (*this);
        }
    }

    if (descending)
    {
        std::reverse(result.begin(), result.end());
    }

    return result;
}

scalar_t scalar_t::pow_sum(size_t count) const
{
    // Computes 1 + x + x^2 + ... + x^(count-1) using repeated doubling:
    // S(2n) = S(n) * (1 + x^n), requiring only O(log n) multiplications
    const bool is_power_of_2 = (count & (count - 1)) == 0;

    if (!is_power_of_2)
    {
        throw std::runtime_error("must be a power of 2");
    }

    if (count == 0)
    {
        return {0};
    }

    if (count == 1)
    {
        return scalar_t(1);
    }

    scalar_t result(1), base(this->serialize());

    result += base;

    while (count > 2)
    {
        base *= base;

        result += result * base;

        count /= 2;
    }

    return result;
}

scalar_t scalar_t::random()
{
    unsigned char bytes[CRYPTO_ENTROPY_BYTES] = {0};

    randompp::random_bytes(CRYPTO_ENTROPY_BYTES, bytes);

    SerializablePod result;

    tinysha_sha3_256(bytes, CRYPTO_ENTROPY_BYTES, *result, result.size());

    ed25519_secure_erase(bytes, sizeof(bytes));

    return scalar_t(result.serialize(), true);
}

std::vector<scalar_t> scalar_t::random(size_t count)
{
    std::vector<scalar_t> result(count);

    for (size_t i = 0; i < count; ++i)
    {
        result[i] = scalar_t::random();
    }

    return result;
}

scalar_t scalar_t::reduce() const
{
    return scalar_t(std::vector<unsigned char>(std::begin(bytes), std::end(bytes)), true);
}

scalar_t scalar_t::squared() const
{
    scalar_t result;

    sc_mul(result.bytes, bytes, bytes);

    return result;
}

std::vector<scalar_t> scalar_t::to_bits(size_t bits) const
{
    if (bits > 256)
    {
        throw std::range_error("requested bit length exceeds maximum scalar bit length");
    }

    std::vector<scalar_t> result;

    result.reserve(bits);

    size_t offset = 0;

    uint64_t temp;

    // Loop until we have the number of requested bits
    while (result.size() != bits)
    {
        /**
         * Load the first 8-bytes (64 bits) into a uint64_t to make it easier
         * to manipulate using standard bit shifts
         */
        std::memcpy(&temp, std::begin(bytes) + offset, 8);

        // Loop through the 64-bits in the uint64_t
        for (size_t i = 0; i < 64; i++)
        {
            // Once we have the requested number of bits, break the loop
            if (result.size() == bits)
            {
                break;
            }

            const scalar_t bit((temp >> i) & 0x01);

            result.push_back(bit);
        }

        // Adjust the offset in the event we need more than 64-bits from the scalar
        offset += sizeof(temp);
    }

    return result;
}

uint64_t scalar_t::to_uint64_t() const
{
    uint64_t result;

    std::memcpy(&result, &bytes, sizeof(result));

    return result;
}

uint256_t scalar_t::to_uint256_t() const
{
    /**
     * uint256_t presumes that we are always working in big-endian when loading from
     * hexadecimal; however, the vast majority of our work in hex is little-endian
     * and as a result, we need to reverse the order of the array to arrive at the
     * correct value being stored in the uint256_t
     */

    unsigned char temp[32] = {0};

    std::memcpy(temp, bytes, sizeof(bytes));

    std::reverse(std::begin(temp), std::end(temp));

    const auto hex = Serialization::to_hex(temp, sizeof(temp));

    uint256_t result(hex, 16);

    return result;
}

bool scalar_t::valid(bool allow_zero) const
{
    if (allow_zero)
    {
        return check();
    }

    return check() && !empty();
}

void scalar_t::do_reduce()
{
    // RFC-8032 clamping (clear low 3 bits, set bit 254, clear bit 255)
    // followed by reduction mod l to ensure the result is a valid scalar
    sc_clamp(bytes);

    sc_reduce(bytes, 32);
}

void scalar_t::from_bits(const std::vector<scalar_t> &bits)
{
    constexpr size_t bits_mod = 32;

    // set all bytes to zero
    std::fill(std::begin(bytes), std::end(bytes), 0);

    if (bits.empty())
    {
        return;
    }

    if (bits.size() > 256)
    {
        throw std::range_error("from_bits() supports a maximum of 256 bits");
    }

    const scalar_t ZERO = {0}, ONE = scalar_t(1);

    size_t offset = 0;

    uint32_t tmp = 0;

    // loop through the individual bits
    for (size_t i = 0; i < bits.size(); ++i)
    {
        if (bits[i] != ZERO && bits[i] != ONE)
        {
            throw std::range_error("individual bit scalar values must be zero (0) or one (1)");
        }

        /**
         * If we are not at the start of the bits supplied and we have consumed
         * enough bits to complete a uint32_t, then move it on to the byte stack
         */
        if (i != 0 && i % bits_mod == 0)
        {
            // move the current uint32_t into the bytes
            std::memcpy(bytes + offset, &tmp, sizeof(tmp));

            // reset the uint32_t
            tmp = 0;

            // increment the offset by the size of the uint32_t
            offset += sizeof(tmp);
        }

        // if the bit is one (1) then we need to shift it into place
        if (bits[i] == 1)
        {
            tmp |= 1u << (i % bits_mod);
        }
    }

    // move the current uint32_t into the bytes at the current offset
    std::memcpy(bytes + offset, &tmp, sizeof(tmp));
}
