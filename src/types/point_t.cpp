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
 * @file point_t.cpp
 * @brief Ed25519 curve point operations with cached ge representations.
 */

#include <core/crypto_config.h>
#include <ed25519/include/ed25519_secure_erase.h>
#include <randompp.hpp>
#include <tinysha.h>
#include <types/point_t.h>

// Ed25519 identity point (0, 1) in compressed form: Y=1 with sign bit 0
static unsigned char z_point[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

point_t::point_t()
{
    std::memcpy(bytes, &z_point, sizeof(z_point));

    load_hook();
}

point_t::point_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

point_t::point_t(const std::vector<unsigned char> &input)
{
    if (input.size() != sizeof(bytes))
    {
        // Malformed-input contract: wrong byte length is a caller mistake
        // and is signaled as std::invalid_argument. The downstream curve
        // decode step (see load_hook below) also throws
        // std::invalid_argument for the "decodes to nothing on the curve"
        // case. Both are malformed-input signals, not internal failures.
        throw std::invalid_argument("point_t: input must be 32 bytes");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

point_t::point_t(const std::string &s)
{
    from_string(s);
}

point_t::point_t(const char *value)
{
    const auto str = std::string(value);

    from_string(str);
}

point_t::point_t(const ge_p3 &point): point3(point)
{
    ge_p3_tobytes(bytes, &point);

    ge_p3_to_cached(&cached_point, &point3);
}

point_t::point_t(const uint64_t &number)
{
    std::memcpy(bytes, &number, sizeof(number));

    load_hook();
}

point_t::~point_t()
{
    // Wipe all representations to prevent key material from lingering in memory
    // Note: bytes is auto-erased by ~SerializablePod<32>()

    ed25519_secure_erase(&point3, sizeof(point3));

    ed25519_secure_erase(&cached_point, sizeof(cached_point));
}

point_t point_t::from_uint256(const uint256_t &number)
{
    unsigned char bytes[32];

    std::memcpy(bytes, &number, sizeof(number));

    return point_t(std::vector<unsigned char>(std::begin(bytes), std::end(bytes)));
}

point_t point_t::operator+(const point_t &other) const
{
    ge_p1p1 tmp2 = {};

    // Point addition using cached representation of RHS for efficiency
    ge_add(&tmp2, &point3, &other.cached_point);

    ge_p3 final = {};

    ge_p1p1_to_p3(&final, &tmp2);

    return point_t(final);
}

void point_t::operator+=(const point_t &other)
{
    *this = *this + other;
}

point_t point_t::operator-(const point_t &other) const
{
    ge_p1p1 tmp2 = {};

    // Point subtraction using cached representation of RHS for efficiency
    ge_sub(&tmp2, &point3, &other.cached_point);

    ge_p3 final = {};

    ge_p1p1_to_p3(&final, &tmp2);

    return point_t(final);
}

point_t point_t::operator-() const
{
    // Unary negation: identity - P = -P
    point_t other({1}); // identity point (0, 1)

    return other - *this;
}

void point_t::operator-=(const point_t &other)
{
    *this = *this - other;
}

ge_cached point_t::cached() const
{
    return cached_point;
}

bool point_t::check() const
{
    ge_p3 tmp = {};

    return ge_frombytes_vartime(&tmp, bytes) == 0;
}

bool point_t::check_subgroup() const
{
    // Verify the point lies in the prime-order subgroup (not a small-subgroup element)
    ge_dsmp tmp;

    ge_dsm_precomp(tmp, &point3);

    return ge_check_subgroup_precomp_negate_vartime(tmp) == 0 && !empty();
}

bool point_t::empty() const
{
    return *this == point_t();
}

point_t point_t::mul8() const
{
    // Multiply by cofactor 8 to project into the prime-order subgroup
    ge_p1p1 tmp = {};

    ge_p2 point2 = {};

    ge_p3_to_p2(&point2, &point3);

    ge_mul8(&tmp, &point2);

    ge_p3 tmp2 = {};

    ge_p1p1_to_p3(&tmp2, &tmp);

    return point_t(tmp2);
}

point_t point_t::negate() const
{
    // Negate in extended coordinates: -P = (-X, Y, Z, -T) but since Ed25519
    // compressed form encodes the sign of X in the high bit of Y, we negate Y
    // in the internal representation to flip the X-coordinate sign on re-encoding.
    ge_p3 tmp = {};

    fe_copy(tmp.X, point3.X);

    fe_neg(tmp.Y, point3.Y);

    fe_copy(tmp.T, point3.T);

    fe_copy(tmp.Z, point3.Z);

    return point_t(tmp);
}

ge_p3 point_t::p3() const
{
    return point3;
}


point_t point_t::random()
{
    unsigned char bytes[CRYPTO_ENTROPY_BYTES] = {0};

    randompp::random_bytes(CRYPTO_ENTROPY_BYTES, bytes);

    SerializablePod result;

    tinysha_sha3_256(bytes, CRYPTO_ENTROPY_BYTES, *result, result.size());

    ed25519_secure_erase(bytes, sizeof(bytes));

    return point_t::reduce(result.data());
}

std::vector<point_t> point_t::random(size_t count)
{
    std::vector<point_t> result(count);

    for (size_t i = 0; i < count; ++i)
    {
        result[i] = point_t::random();
    }

    return result;
}

point_t point_t::reduce(const unsigned char *bytes)
{
    // Hash-to-curve: Elligator map to get a curve point, then mul8 to clear
    // the cofactor and land in the prime-order subgroup
    ge_p2 point = {};

    ge_p1p1 point2 = {};

    ge_p3 point3 = {};

    ge_fromfe_frombytes_vartime(&point, bytes);

    ge_mul8(&point2, &point);

    ge_p1p1_to_p3(&point3, &point2);

    return point_t(point3);
}

uint256_t point_t::to_uint256_t() const
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

bool point_t::valid(bool allow_identity) const
{
    if (allow_identity)
    {
        return check();
    }

    return check() && !empty();
}

void point_t::load_hook()
{
    // Decode compressed point and pre-compute both ge_p3 and ge_cached forms.
    // ge_cached is needed for efficient point addition/subtraction later.
    if (ge_frombytes_vartime(&point3, bytes) != 0)
    {
        // Malformed-input contract: bytes don't decode to any point on
        // the Ed25519 curve. This is a caller mistake (bad wire format,
        // adversarial input, corruption) — NOT an internal failure — so
        // we throw std::invalid_argument, matching the wire-length check
        // in the vector constructor above.
        throw std::invalid_argument("point_t: bytes do not decode to a valid Ed25519 curve point");
    }

    ge_p3_to_cached(&cached_point, &point3);
}
