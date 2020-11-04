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
#include <cryptopp/blake2.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <helpers/random_bytes.h>
#include <types/crypto_hash_t.h>

extern "C"
{
#include <argon2.h>
}

static bool argon2_optimization_selected = false;

static void init_argon2()
{
    /**
     * If this is the first time that this method has been called, then
     * we need to run the argon2 selection method to determine the
     * best intrinsics to use for the CPU that we are running on
     */
    if (!argon2_optimization_selected)
    {
        argon2_select_impl(NULL, NULL);

        argon2_optimization_selected = true;
    }
}

crypto_hash_t::crypto_hash_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));
}

crypto_hash_t::crypto_hash_t(const std::vector<unsigned char> &input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));
}

crypto_hash_t::crypto_hash_t(const char *value)
{
    const auto str = std::string(value);

    from_string(str);
}

crypto_hash_t crypto_hash_t::argon2d(
    const void *input,
    size_t length,
    const void *salt,
    size_t salt_length,
    size_t iterations,
    size_t memory,
    size_t threads)
{
    init_argon2();

    crypto_hash_t result;

    argon2d_hash_raw(iterations, memory, threads, input, length, salt, salt_length, *result, result.size());

    return result;
}

crypto_hash_t crypto_hash_t::argon2i(
    const void *input,
    size_t length,
    const void *salt,
    size_t salt_length,
    size_t iterations,
    size_t memory,
    size_t threads)
{
    init_argon2();

    crypto_hash_t result;

    argon2i_hash_raw(iterations, memory, threads, input, length, salt, salt_length, *result, result.size());

    return result;
}

crypto_hash_t crypto_hash_t::argon2id(
    const void *input,
    size_t length,
    const void *salt,
    size_t salt_length,
    size_t iterations,
    size_t memory,
    size_t threads)
{
    init_argon2();

    crypto_hash_t result;

    argon2id_hash_raw(iterations, memory, threads, input, length, salt, salt_length, *result, result.size());

    return result;
}

crypto_hash_t crypto_hash_t::blake2b(const void *input, size_t length)
{
    crypto_hash_t result;

    auto hash_context = new CryptoPP::BLAKE2b(false, static_cast<unsigned int>(result.size()));

    hash_context->Update(static_cast<const CryptoPP::byte *>(input), length);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return result;
}

size_t crypto_hash_t::hex_leading_zeros(bool reversed) const
{
    // take the leading zero in bits and divide it by nibbles (4-bits)
    return leading_zeros(reversed) / 4;
}

crypto_hash_t crypto_hash_t::random()
{
    unsigned char bytes[CRYPTO_ENTROPY_BYTES] = {0};

    random_bytes(CRYPTO_ENTROPY_BYTES, bytes);

    crypto_hash_t result;

    const auto hash_context = new CryptoPP::SHA3_512();

    hash_context->Update(bytes, CRYPTO_ENTROPY_BYTES);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return result;
}

std::vector<crypto_hash_t> crypto_hash_t::random(size_t count)
{
    std::vector<crypto_hash_t> result(count);

    for (size_t i = 0; i < count; ++i)
    {
        result[i] = crypto_hash_t::random();
    }

    return result;
}

crypto_hash_t crypto_hash_t::sha3(const void *input, size_t length)
{
    crypto_hash_t result;

    const auto hash_context = new CryptoPP::SHA3_256();

    hash_context->Update(static_cast<const CryptoPP::byte *>(input), length);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return result;
}

crypto_hash_t crypto_hash_t::sha3_slow(const void *input, size_t length, uint64_t iterations)
{
    Serialization::serializer_t writer;

    auto result = crypto_hash_t::sha3(input, length);

    for (uint64_t i = 0; i < iterations; ++i)
    {
        writer.reset();

        writer.pod(result);

        writer.uint64(i);

        result = crypto_hash_t::sha3(writer.data(), writer.size());
    }

    return result;
}

crypto_hash_t crypto_hash_t::sha256(const void *input, size_t length)
{
    crypto_hash_t result;

    const auto hash_context = new CryptoPP::SHA256();

    hash_context->Update(static_cast<const CryptoPP::byte *>(input), length);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return result;
}

crypto_hash_t crypto_hash_t::sha384(const void *input, size_t length)
{
    crypto_hash_t result;

    const auto hash_context = new CryptoPP::SHA384();

    hash_context->Update(static_cast<const CryptoPP::byte *>(input), length);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return result;
}

crypto_hash_t crypto_hash_t::sha512(const void *input, size_t length)
{
    crypto_hash_t result;

    const auto hash_context = new CryptoPP::SHA512();

    hash_context->Update(static_cast<const CryptoPP::byte *>(input), length);

    hash_context->TruncatedFinal(*result, result.size());

    free(hash_context);

    return result;
}

size_t crypto_hash_t::leading_zeros(bool reversed) const
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

crypto_point_t crypto_hash_t::point() const
{
    return crypto_point_t::reduce(this->data());
}

crypto_scalar_t crypto_hash_t::scalar() const
{
    return crypto_scalar_t(this->serialize(), true);
}

std::vector<unsigned char> crypto_hash_t::to_bits(bool reversed) const
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

uint256_t crypto_hash_t::to_uint256_t() const
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
