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
#include <types/crypto_point_t.h>

static unsigned char z_point[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

crypto_point_t::crypto_point_t()
{
    std::memcpy(bytes, &z_point, sizeof(z_point));

    load_hook();
}

crypto_point_t::crypto_point_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

crypto_point_t::crypto_point_t(const std::vector<unsigned char> &input)
{
    if (input.size() != sizeof(bytes))
    {
        throw std::runtime_error("could not load point");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

crypto_point_t::crypto_point_t(const std::string &s)
{
    from_string(s);
}

crypto_point_t::crypto_point_t(const char *value)
{
    const auto str = std::string(value);

    from_string(str);
}

crypto_point_t::crypto_point_t(const ge_p3 &point): point3(point)
{
    ge_p3_tobytes(bytes, &point);

    ge_p3_to_cached(&cached_point, &point3);
}

crypto_point_t::crypto_point_t(const uint64_t &number)
{
    std::memcpy(bytes, &number, sizeof(number));

    load_hook();
}

crypto_point_t::~crypto_point_t()
{
    secure_erase(bytes, sizeof(bytes));

    secure_erase(&point3, sizeof(point3));

    secure_erase(&cached_point, sizeof(cached_point));
}

crypto_point_t crypto_point_t::from_uint256(const uint256_t &number)
{
    unsigned char bytes[32];

    std::memcpy(bytes, &number, sizeof(number));

    return crypto_point_t(std::vector<unsigned char>(std::begin(bytes), std::end(bytes)));
}

crypto_point_t crypto_point_t::operator+(const crypto_point_t &other) const
{
    ge_p1p1 tmp2;

    // AB = (a + b) mod l
    ge_add(&tmp2, &point3, &other.cached_point);

    ge_p3 final;

    ge_p1p1_to_p3(&final, &tmp2);

    return crypto_point_t(final);
}

void crypto_point_t::operator+=(const crypto_point_t &other)
{
    *this = *this + other;
}

crypto_point_t crypto_point_t::operator-(const crypto_point_t &other) const
{
    ge_p1p1 tmp2;

    // AB = (a - b) mod l
    ge_sub(&tmp2, &point3, &other.cached_point);

    ge_p3 final;

    ge_p1p1_to_p3(&final, &tmp2);

    return crypto_point_t(final);
}

crypto_point_t crypto_point_t::operator-() const
{
    crypto_point_t other({1}); // Z = (0, 1)

    return other - *this;
}

void crypto_point_t::operator-=(const crypto_point_t &other)
{
    *this = *this - other;
}

ge_cached crypto_point_t::cached() const
{
    return cached_point;
}

bool crypto_point_t::check() const
{
    ge_p3 tmp;

    return ge_frombytes_negate_vartime(&tmp, bytes) == 0;
}

bool crypto_point_t::check_subgroup() const
{
    ge_dsmp tmp;

    ge_dsm_precomp(tmp, &point3);

    return ge_check_subgroup_precomp_negate_vartime(tmp) == 0 && !empty();
}

bool crypto_point_t::empty() const
{
    return *this == crypto_point_t();
}

crypto_point_t crypto_point_t::mul8() const
{
    ge_p1p1 tmp;

    ge_p2 point2;

    ge_p3_to_p2(&point2, &point3);

    ge_mul8(&tmp, &point2);

    ge_p3 tmp2;

    ge_p1p1_to_p3(&tmp2, &tmp);

    return crypto_point_t(tmp2);
}

crypto_point_t crypto_point_t::negate() const
{
    ge_p3 tmp;

    fe_copy(tmp.X, point3.X);

    // Flip the sign on the Y-coordinate
    fe_neg(tmp.Y, point3.Y);

    fe_copy(tmp.T, point3.T);

    fe_copy(tmp.Z, point3.Z);

    return crypto_point_t(tmp);
}

ge_p3 crypto_point_t::p3() const
{
    return point3;
}


crypto_point_t crypto_point_t::random()
{
    unsigned char bytes[CRYPTO_ENTROPY_BYTES] = {0};

    random_bytes(CRYPTO_ENTROPY_BYTES, bytes);

    SerializablePod result;

    auto hash_context = new CryptoPP::SHA3_256();

    hash_context->Update(static_cast<CryptoPP::byte *>(bytes), CRYPTO_ENTROPY_BYTES);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return crypto_point_t::reduce(result.data());
}

std::vector<crypto_point_t> crypto_point_t::random(size_t count)
{
    std::vector<crypto_point_t> result(count);

    for (size_t i = 0; i < count; ++i)
    {
        result[i] = crypto_point_t::random();
    }

    return result;
}

crypto_point_t crypto_point_t::reduce(const unsigned char *bytes)
{
    ge_p2 point;

    ge_p1p1 point2;

    ge_p3 point3;

    ge_fromfe_frombytes_negate_vartime(&point, bytes);

    ge_mul8(&point2, &point);

    ge_p1p1_to_p3(&point3, &point2);

    return crypto_point_t(point3);
}

uint256_t crypto_point_t::to_uint256_t() const
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

bool crypto_point_t::valid(bool allow_identity) const
{
    if (allow_identity)
    {
        return check();
    }

    return check() && !empty();
}

void crypto_point_t::load_hook()
{
    if (ge_frombytes_negate_vartime(&point3, bytes) != 0)
    {
        throw std::runtime_error("could not load point");
    }

    ge_p3_to_cached(&cached_point, &point3);
}
