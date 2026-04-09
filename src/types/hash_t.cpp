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
 * @file hash_t.cpp
 * @brief Hash type implementations: SHA3, SHA2, BLAKE2b, Argon2, and hash-to-curve/scalar conversions.
 */

#include <core/crypto_config.h>
#include <mutex>
#include <randompp.hpp>
#include <tinyblake.h>
#include <tinysha.h>
#include <types/hash_t.h>

extern "C"
{
#include <argon2.h>
}

static std::once_flag argon2_init_flag;

static void init_argon2()
{
    /**
     * Thread-safe one-time initialization using std::call_once to prevent
     * data races when multiple threads call Argon2 functions concurrently.
     */
    std::call_once(argon2_init_flag, []() { argon2_select_impl(NULL, NULL); });
}

hash_t::hash_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));
}

hash_t::hash_t(const std::vector<unsigned char> &input)
{
    if (input.size() > sizeof(bytes))
    {
        // Malformed-input contract: input longer than the 32-byte hash
        // size is a caller mistake, not an internal failure. Throws
        // std::invalid_argument so downstream fuzz harnesses and
        // validators classify this as "bad input, safe to reject"
        // (std::runtime_error is reserved for invariant violations).
        throw std::invalid_argument("hash_t: input must be <= 32 bytes");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));
}

hash_t::hash_t(const char *value)
{
    const auto str = std::string(value);

    from_string(str);
}

hash_t hash_t::argon2d(
    const void *input,
    size_t length,
    const void *salt,
    size_t salt_length,
    size_t iterations,
    size_t memory,
    size_t threads)
{
    init_argon2();

    hash_t result;

    argon2d_hash_raw(iterations, memory, threads, input, length, salt, salt_length, *result, result.size());

    return result;
}

hash_t hash_t::argon2i(
    const void *input,
    size_t length,
    const void *salt,
    size_t salt_length,
    size_t iterations,
    size_t memory,
    size_t threads)
{
    init_argon2();

    hash_t result;

    argon2i_hash_raw(iterations, memory, threads, input, length, salt, salt_length, *result, result.size());

    return result;
}

hash_t hash_t::argon2id(
    const void *input,
    size_t length,
    const void *salt,
    size_t salt_length,
    size_t iterations,
    size_t memory,
    size_t threads)
{
    init_argon2();

    hash_t result;

    argon2id_hash_raw(iterations, memory, threads, input, length, salt, salt_length, *result, result.size());

    return result;
}

hash_t hash_t::blake2b(const void *input, size_t length)
{
    hash_t result;

    tinyblake_blake2b(*result, result.size(), input, length, NULL, 0);

    return result;
}

size_t hash_t::hex_leading_zeros(bool reversed) const
{
    // take the leading zero in bits and divide it by nibbles (4-bits)
    return leading_zeros(reversed) / 4;
}

hash_t hash_t::random()
{
    unsigned char bytes[CRYPTO_ENTROPY_BYTES] = {0};

    randompp::random_bytes(CRYPTO_ENTROPY_BYTES, bytes);

    hash_t result;

    tinysha_sha3_512(bytes, CRYPTO_ENTROPY_BYTES, *result, result.size());

    return result;
}

std::vector<hash_t> hash_t::random(size_t count)
{
    std::vector<hash_t> result(count);

    for (size_t i = 0; i < count; ++i)
    {
        result[i] = hash_t::random();
    }

    return result;
}

hash_t hash_t::sha3(const void *input, size_t length)
{
    hash_t result;

    tinysha_sha3_256(static_cast<const uint8_t *>(input), length, *result, result.size());

    return result;
}

hash_t hash_t::sha3_slow(const void *input, size_t length, uint64_t iterations)
{
    // Key-stretching: iteratively re-hash with a counter to increase computational cost.
    // Each round feeds H(prev_hash || iteration_index) to make the output depend on all rounds.
    Serialization::serializer_t writer;

    auto result = hash_t::sha3(input, length);

    for (uint64_t i = 0; i < iterations; ++i)
    {
        writer.reset();

        writer.pod(result);

        writer.uint64(i);

        result = hash_t::sha3(writer.data(), writer.size());
    }

    return result;
}

hash_t hash_t::sha256(const void *input, size_t length)
{
    hash_t result;

    tinysha_sha256(static_cast<const uint8_t *>(input), length, *result, result.size());

    return result;
}

hash_t hash_t::sha384(const void *input, size_t length)
{
    hash_t result;

    tinysha_sha384(static_cast<const uint8_t *>(input), length, *result, result.size());

    return result;
}

hash_t hash_t::sha512(const void *input, size_t length)
{
    hash_t result;

    tinysha_sha512(static_cast<const uint8_t *>(input), length, *result, result.size());

    return result;
}

size_t hash_t::leading_zeros(bool reversed) const
{
    size_t count = 0;

    const auto bits = to_bits(reversed);

    for (const auto &bit : bits)
    {
        if (bit != 0)
        {
            break;
        }

        count++;
    }

    return count;
}

point_t hash_t::point() const
{
    // Hash-to-curve via Elligator map + cofactor clearing (see point_t::reduce)
    return point_t::reduce(this->data());
}

scalar_t hash_t::scalar() const
{
    // Pure mod-l reduction of the 32-byte hash output -- NO CLAMPING. Every
    // scalar_transcript_t::update() call ends with `state = hash_t::sha3(...).scalar()`,
    // so this is the transcript hot path and must never apply sc_clamp. The residual
    // ~2^-124 bias from 32-byte mod-l reduction is statistically undetectable and not
    // lattice-exploitable. Callers needing fully-unbiased hash-to-scalar should use
    // scalar_t::from_uniform_bytes() with a 64-byte hash instead.
    //
    // from_bytes_reduced is a single-memcpy + sc_reduce fast path that avoids the
    // intermediate std::vector allocation and double copy that would result from
    // going through serialize() + scalar_t(vector) + .reduce().
    return scalar_t::from_bytes_reduced(bytes);
}

std::vector<unsigned char> hash_t::to_bits(bool reversed) const
{
    const auto bits = sizeof(bytes) * 8;

    std::vector<unsigned char> result, temp;

    result.reserve(bits);

    for (const auto &byte : bytes)
    {
        temp.clear();

        for (size_t j = 0; j < 8; ++j)
        {
            const unsigned char bit((byte >> j) & 0x01);

            temp.push_back(bit);
        }

        std::reverse(temp.begin(), temp.end());

        for (const auto &bit : temp)
        {
            result.push_back(bit);
        }
    }

    if (reversed)
    {
        std::reverse(result.begin(), result.end());
    }

    return result;
}

uint256_t hash_t::to_uint256_t() const
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
