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

#include <crypto_config.h>
#include <cryptopp/sha3.h>
#include <helpers/random_bytes.h>
#include <types/crypto_scalar_t.h>

crypto_scalar_t::crypto_scalar_t(std::initializer_list<unsigned char> input, bool reduce)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));

    if (reduce)
    {
        do_reduce();
    }
}

crypto_scalar_t::crypto_scalar_t(const std::vector<unsigned char> &input, bool reduce)
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

crypto_scalar_t::crypto_scalar_t(const std::string &s, bool reduce)
{
    from_string(s);

    if (reduce)
    {
        do_reduce();
    }
}

crypto_scalar_t::crypto_scalar_t(const uint64_t &number, bool reduce)
{
    std::memcpy(bytes, &number, sizeof(number));

    if (reduce)
    {
        do_reduce();
    }
}

crypto_scalar_t::crypto_scalar_t(const char *value, bool reduce)
{
    const auto str = std::string(value);

    from_string(str);

    if (reduce)
    {
        do_reduce();
    }
}

crypto_scalar_t::crypto_scalar_t(const std::vector<crypto_scalar_t> &bits, bool reduce)
{
    from_bits(bits);

    if (reduce)
    {
        do_reduce();
    }
}

crypto_scalar_t crypto_scalar_t::from_uint256(const uint256_t &number, bool reduce)
{
    unsigned char bytes[32];

    std::memcpy(bytes, &number, sizeof(number));

    auto result = crypto_scalar_t(std::vector<unsigned char>(std::begin(bytes), std::end(bytes)));

    if (reduce)
    {
        return result.reduce();
    }

    return result;
}

bool crypto_scalar_t::operator==(const crypto_scalar_t &other) const
{
    return std::equal(std::begin(bytes), std::end(bytes), std::begin(other.bytes));
}

bool crypto_scalar_t::operator==(const uint64_t &other) const
{
    const auto other_scalar = crypto_scalar_t(other);

    return (*this == other_scalar);
}

bool crypto_scalar_t::operator==(const uint256_t &other) const
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    return (*this == other_scalar);
}

bool crypto_scalar_t::operator!=(const crypto_scalar_t &other) const
{
    return !(*this == other);
}

bool crypto_scalar_t::operator!=(const uint64_t &other) const
{
    return !(*this == other);
}

bool crypto_scalar_t::operator!=(const uint256_t &other) const
{
    return !(*this == other);
}

bool crypto_scalar_t::operator<(const crypto_scalar_t &other) const
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

bool crypto_scalar_t::operator<(const uint64_t &other) const
{
    const auto other_scalar = crypto_scalar_t(other);

    return (*this < other_scalar);
}

bool crypto_scalar_t::operator<(const uint256_t &other) const
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    return (*this < other_scalar);
}

bool crypto_scalar_t::operator<=(const uint64_t &other) const
{
    return (*this < other) || (*this == other);
}

bool crypto_scalar_t::operator<=(const uint256_t &other) const
{
    return (*this < other) || (*this == other);
}

bool crypto_scalar_t::operator>(const crypto_scalar_t &other) const
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

bool crypto_scalar_t::operator>(const uint64_t &other) const
{
    const auto other_scalar = crypto_scalar_t(other);

    return (*this < other_scalar);
}

bool crypto_scalar_t::operator>(const uint256_t &other) const
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    return (*this < other_scalar);
}

bool crypto_scalar_t::operator>=(const uint64_t &other) const
{
    return (*this > other) || (*this == other);
}

bool crypto_scalar_t::operator>=(const uint256_t &other) const
{
    return (*this > other) || (*this == other);
}

crypto_scalar_t crypto_scalar_t::operator+(const crypto_scalar_t &other) const
{
    crypto_scalar_t result;

    sc_add(result.bytes, bytes, other.bytes);

    return result;
}

crypto_scalar_t crypto_scalar_t::operator+(const uint64_t &other) const
{
    const auto other_scalar = crypto_scalar_t(other);

    return (*this + other_scalar);
}

crypto_scalar_t crypto_scalar_t::operator+(const uint256_t &other) const
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    return (*this + other_scalar);
}

void crypto_scalar_t::operator+=(const crypto_scalar_t &other)
{
    sc_add(bytes, bytes, other.bytes);
}

void crypto_scalar_t::operator+=(const uint64_t &other)
{
    const auto other_scalar = crypto_scalar_t(other);

    *this += other_scalar;
}

void crypto_scalar_t::operator+=(const uint256_t &other)
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    *this += other_scalar;
}

crypto_scalar_t crypto_scalar_t::operator-(const crypto_scalar_t &other) const
{
    crypto_scalar_t result;

    sc_sub(result.bytes, bytes, other.bytes);

    return result;
}

crypto_scalar_t crypto_scalar_t::operator-(const uint64_t &other) const
{
    const auto other_scalar = crypto_scalar_t(other);

    return (*this - other_scalar);
}

crypto_scalar_t crypto_scalar_t::operator-(const uint256_t &other) const
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    return (*this - other_scalar);
}

void crypto_scalar_t::operator-=(const crypto_scalar_t &other)
{
    sc_sub(bytes, bytes, other.bytes);
}

void crypto_scalar_t::operator-=(const uint64_t &other)
{
    const auto other_scalar = crypto_scalar_t(other);

    *this -= other_scalar;
}

void crypto_scalar_t::operator-=(const uint256_t &other)
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    *this -= other_scalar;
}

crypto_scalar_t crypto_scalar_t::operator*(const crypto_scalar_t &other) const
{
    crypto_scalar_t result;

    sc_mul(result.bytes, bytes, other.bytes);

    return result;
}

crypto_scalar_t crypto_scalar_t::operator*(const uint64_t &other) const
{
    const auto other_scalar = crypto_scalar_t(other);

    return (*this * other_scalar);
}

crypto_scalar_t crypto_scalar_t::operator*(const uint256_t &other) const
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    return (*this * other_scalar);
}

void crypto_scalar_t::operator*=(const crypto_scalar_t &other)
{
    sc_mul(bytes, bytes, other.bytes);
}

void crypto_scalar_t::operator*=(const uint64_t &other)
{
    const auto other_scalar = crypto_scalar_t(other);

    *this *= other_scalar;
}

void crypto_scalar_t::operator*=(const uint256_t &other)
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    *this *= other_scalar;
}

crypto_scalar_t crypto_scalar_t::operator/(const crypto_scalar_t &other) const
{
    return *this * other.invert();
}

crypto_scalar_t crypto_scalar_t::operator/(const uint64_t &other) const
{
    const auto other_scalar = crypto_scalar_t(other);

    return (*this / other_scalar);
}

crypto_scalar_t crypto_scalar_t::operator/(const uint256_t &other) const
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    return (*this / other_scalar);
}

void crypto_scalar_t::operator/=(const crypto_scalar_t &other)
{
    *this = *this / other;
}

void crypto_scalar_t::operator/=(const uint64_t &other)
{
    const auto other_scalar = crypto_scalar_t(other);

    *this /= other_scalar;
}

void crypto_scalar_t::operator/=(const uint256_t &other)
{
    const auto other_scalar = crypto_scalar_t::from_uint256(other);

    *this /= other_scalar;
}

crypto_point_t crypto_scalar_t::operator*(const crypto_point_t &point) const
{
    ge_p3 temp_p3;

    ge_p1p1 temp_p1p1;

    if (point == Crypto::G) // If we're multiplying by G, use the base method, it's faster
    {
        ge_scalarmult_base(&temp_p1p1, bytes);

        ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

        return crypto_point_t(temp_p3);
    }
    else
    {
        const auto p = point.p3();

        // aB = (a * B) mod l
        ge_scalarmult(&temp_p1p1, bytes, &p);

        ge_p1p1_to_p3(&temp_p3, &temp_p1p1);

        return crypto_point_t(temp_p3);
    }
}

crypto_point_t
    crypto_scalar_t::dbl_mult(const crypto_point_t &A, const crypto_scalar_t &b, const crypto_point_t &B) const
{
    ge_p1p1 temp_p1p1;

    ge_p3 temp_p3;

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

    crypto_point_t point(temp_p3);

    if (point != Crypto::ZP)
    {
        return point;
    }

    return Crypto::Z;
}

bool crypto_scalar_t::check() const
{
    return sc_check(bytes) == 0;
}

crypto_scalar_t crypto_scalar_t::invert() const
{
    // equivalent to x^(l-2)
    return pow({0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10});
}

bool crypto_scalar_t::is_nonzero() const
{
    return sc_isnonzero(bytes) == 0;
}

crypto_scalar_t crypto_scalar_t::negate() const
{
    crypto_scalar_t zero({0});

    return zero - *this;
}

crypto_point_t crypto_scalar_t::point() const
{
    return *this * Crypto::G;
}

crypto_scalar_t crypto_scalar_t::pow(const crypto_scalar_t &exponent) const
{
    // convert our exponent to a vector of 256 individual bits
    const auto bits = exponent.to_bits(256);

    crypto_scalar_t result(1), m(this->serialize());

    size_t upper_bound = 0;

    /**
     * Locate the highest set bit to limit the range of our loop
     * thus reducing the number of scalar multiplications performed
     */
    for (size_t i = 0; i < bits.size(); ++i)
    {
        if (bits[i][0] == 1)
        {
            upper_bound = i;
        }
    }

    /**
     * Use the double-and-multiply method to calculate the value which results in us
     * performing at maximum, 512 scalar multiplication operations.
     */
    for (size_t i = 0; i <= upper_bound; ++i)
    {
        if (bits[i] == 1)
        {
            result *= m;
        }

        m *= m;
    }

    return result;
}

crypto_scalar_t crypto_scalar_t::pow(size_t exponent) const
{
    return pow(crypto_scalar_t(exponent));
}

crypto_scalar_t crypto_scalar_t::powm(const crypto_scalar_t &exponent, size_t modulus) const
{
    return crypto_scalar_t(pow(exponent).to_uint256_t() % modulus);
}

std::vector<crypto_scalar_t> crypto_scalar_t::pow_expand(size_t count, bool descending, bool include_zero) const
{
    if (count == 0)
    {
        throw std::invalid_argument("count should be non-zero");
    }

    std::vector<crypto_scalar_t> result(count);

    size_t start = 0, end = count;

    if (!include_zero)
    {
        start += 1;

        end += 1;
    }

    for (size_t i = start, j = 0; i < end; ++i, ++j)
    {
        result[j] = pow(i);
    }

    if (descending)
    {
        std::reverse(result.begin(), result.end());
    }

    return result;
}

crypto_scalar_t crypto_scalar_t::pow_sum(size_t count) const
{
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
        return crypto_scalar_t(1);
    }

    crypto_scalar_t result(1), base(this->serialize());

    result += base;

    while (count > 2)
    {
        base *= base;

        result += result * base;

        count /= 2;
    }

    return result;
}

crypto_scalar_t crypto_scalar_t::random()
{
    unsigned char bytes[CRYPTO_ENTROPY_BYTES] = {0};

    random_bytes(CRYPTO_ENTROPY_BYTES, bytes);

    SerializablePod result;

    auto hash_context = new CryptoPP::SHA3_256();

    hash_context->Update(static_cast<CryptoPP::byte *>(bytes), CRYPTO_ENTROPY_BYTES);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return crypto_scalar_t(result.serialize(), true);
}

std::vector<crypto_scalar_t> crypto_scalar_t::random(size_t count)
{
    std::vector<crypto_scalar_t> result(count);

    for (size_t i = 0; i < count; ++i)
    {
        result[i] = crypto_scalar_t::random();
    }

    return result;
}

crypto_scalar_t crypto_scalar_t::reduce() const
{
    return crypto_scalar_t(std::vector<unsigned char>(std::begin(bytes), std::end(bytes)), true);
}

crypto_scalar_t crypto_scalar_t::squared() const
{
    crypto_scalar_t result;

    sc_mul(result.bytes, bytes, bytes);

    return result;
}

std::vector<crypto_scalar_t> crypto_scalar_t::to_bits(size_t bits) const
{
    if (bits > 256)
    {
        throw std::range_error("requested bit length exceeds maximum scalar bit length");
    }

    std::vector<crypto_scalar_t> result;

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

            const crypto_scalar_t bit((temp >> i) & 0x01);

            result.push_back(bit);
        }

        // Adjust the offset in the event we need more than 64-bits from the scalar
        offset += sizeof(temp);
    }

    return result;
}

uint64_t crypto_scalar_t::to_uint64_t() const
{
    uint64_t result;

    std::memcpy(&result, &bytes, sizeof(result));

    return result;
}

uint256_t crypto_scalar_t::to_uint256_t() const
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

bool crypto_scalar_t::valid(bool allow_zero) const
{
    if (allow_zero)
    {
        return check();
    }

    return check() && !empty();
}

void crypto_scalar_t::do_reduce()
{
    sc_reduce_rfc(bytes);

    sc_reduce32(bytes);
}

void crypto_scalar_t::from_bits(const std::vector<crypto_scalar_t> &bits)
{
    constexpr size_t bits_mod = 32;

    // set all bytes to zero
    std::fill(std::begin(bytes), std::end(bytes), 0);

    if (bits.empty())
    {
        return;
    }

    const crypto_scalar_t ZERO = {0}, ONE = crypto_scalar_t(1);

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
            tmp |= 1 << (i % bits_mod);
        }
    }

    // move the current uint32_t into the bytes at the current offset
    std::memcpy(bytes + offset, &tmp, sizeof(tmp));
}
