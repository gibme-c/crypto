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

#ifndef CRYPTO_HASH_T
#define CRYPTO_HASH_T

#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * A structure representing a 256-bit hash value
 */
struct crypto_hash_t final : SerializablePod<32>
{
    crypto_hash_t() = default;

    crypto_hash_t(std::initializer_list<unsigned char> input);

    explicit crypto_hash_t(const std::vector<unsigned char> &input);

    JSON_STRING_CONSTRUCTOR(crypto_hash_t, fromJSON)

    explicit crypto_hash_t(const char value[65]);

    /**
     * Hashes the given data with the given salt using Argon2d into a 256-bit hash
     *
     * @param input
     * @param length
     * @param salt
     * @param salt_length
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    static crypto_hash_t argon2d(
        const void *input,
        size_t length,
        const void *salt,
        size_t salt_length,
        size_t iterations = 1,
        size_t memory = 256,
        size_t threads = 1);

    /**
     * Hashes the given vector of data (using itself as salt) using Argon2d into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    template<typename T>
    static crypto_hash_t argon2d(
        const std::vector<T> &input,
        const size_t iterations = 1,
        const size_t memory = 256,
        const size_t threads = 1)
    {
        return crypto_hash_t::argon2d(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data (using itself as salt) using Argon2d into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    template<typename T>
    static crypto_hash_t
        argon2d(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return crypto_hash_t::argon2d(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data with the given salt using Argon2i into a 256-bit hash
     *
     * @param input
     * @param length
     * @param salt
     * @param salt_length
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    static crypto_hash_t argon2i(
        const void *input,
        size_t length,
        const void *salt,
        size_t salt_length,
        size_t iterations = 1,
        size_t memory = 256,
        size_t threads = 1);

    /**
     * Hashes the given vector of data (using itself as salt) using Argon2i into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    template<typename T>
    static crypto_hash_t argon2i(
        const std::vector<T> &input,
        const size_t iterations = 1,
        const size_t memory = 256,
        const size_t threads = 1)
    {
        return crypto_hash_t::argon2i(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data (using itself as salt) using Argon2i into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    template<typename T>
    static crypto_hash_t
        argon2i(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return crypto_hash_t::argon2i(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data with the given salt using Argon2id into a 256-bit hash
     *
     * @param input
     * @param length
     * @param salt
     * @param salt_length
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    static crypto_hash_t argon2id(
        const void *input,
        size_t length,
        const void *salt,
        size_t salt_length,
        size_t iterations = 1,
        size_t memory = 256,
        size_t threads = 1);

    /**
     * Hashes the given vector of data (using itself as salt) using Argon2id into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    template<typename T>
    static crypto_hash_t argon2id(
        const std::vector<T> &input,
        const size_t iterations = 1,
        const size_t memory = 256,
        const size_t threads = 1)
    {
        return crypto_hash_t::argon2id(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data (using itself as salt) using Argon2id into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @param iterations number of iterations
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return
     */
    template<typename T>
    static crypto_hash_t
        argon2id(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return crypto_hash_t::argon2id(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data using Blake2b into a 256-bit hash
     *
     * @param input
     * @param length
     * @return
     */
    static crypto_hash_t blake2b(const void *input, size_t length);

    /**
     * Hashes the given data using Blake2b into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> static crypto_hash_t blake2b(const std::vector<T> &input)
    {
        return crypto_hash_t::blake2b(input.data(), input.size());
    }

    /**
     * Hashes the given data using Blake2b into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> static crypto_hash_t blake2b(const T &input)
    {
        return crypto_hash_t::blake2b(input.data(), input.size());
    }

    /**
     * Returns the number of leading 0s of the hash using it's hexadecimal representation
     * @param reversed
     * @return
     */
    [[nodiscard]] size_t hex_leading_zeros(bool reversed = false) const;

    /**
     * Generates a random crypto hash
     *
     * @return
     */
    [[nodiscard]] static crypto_hash_t random();

    /**
     * Generates a vector of random hashes
     *
     * @param count
     * @return
     */
    [[nodiscard]] static std::vector<crypto_hash_t> random(size_t count);

    /**
     * Hashes the given input data using SHA-3 into a 256-bit hash
     *
     * @param input
     * @param length
     * @return
     */
    static crypto_hash_t sha3(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-3 into a 256-bit hash
     *
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> static crypto_hash_t sha3(const T &input)
    {
        return sha3(input.data(), input.size());
    }

    /**
     * Hashes the given input using SHA-3 for the number of rounds indicated by iterations
     * this method also performs basic key stretching whereby the input data is appended
     * to the resulting hash each round to "salt" each round of hashing to prevent simply
     * iterating the hash over itself
     *
     * @param input
     * @param length
     * @param iterations number of iterations
     * @return
     */
    static crypto_hash_t sha3_slow(const void *input, size_t length, uint64_t iterations);

    /**
     * Hashes the given POD using SHA-3 for the number of rounds indicated by iterations
     * this method also performs basic key stretching whereby the input data is appended
     * to the resulting hash each round to "salt" each round of hashing to prevent simply
     * iterating the hash over itself
     *
     * @tparam T
     * @param input
     * @param iterations number of iterations
     * @return
     */
    template<typename T> static crypto_hash_t sha3_slow(const T &input, uint64_t iterations = 0)
    {
        return sha3_slow(input.data(), input.size(), iterations);
    }

    /**
     * Hashes the given input data using SHA-256 into a 256-bit hash
     * @param input
     * @param length
     * @return
     */
    static crypto_hash_t sha256(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-256 into a 256-bit hash
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> static crypto_hash_t sha256(const T &input)
    {
        return sha256(input.data(), input.size());
    }

    /**
     * Hashes the given input data using SHA-384 into a 256-bit hash
     * @param input
     * @param length
     * @return
     */
    static crypto_hash_t sha384(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-384 into a 256-bit hash
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> static crypto_hash_t sha384(const T &input)
    {
        return sha384(input.data(), input.size());
    }

    /**
     * Hashes the given input data using SHA-512 into a 256-bit hash
     * @param input
     * @param length
     * @return
     */
    static crypto_hash_t sha512(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-512 into a 256-bit hash
     * @tparam T
     * @param input
     * @return
     */
    template<typename T> static crypto_hash_t sha512(const T &input)
    {
        return sha512(input.data(), input.size());
    }

    /**
     * Returns the number of leading 0s of the hash using the bits of the hash
     * @param reversed
     * @return
     */
    [[nodiscard]] size_t leading_zeros(bool reversed = true) const;

    /**
     * Reduces the hash into a point
     *
     * @return
     */
    [[nodiscard]] crypto_point_t point() const;

    /**
     * Reduces the hash into a scalar
     *
     * @return
     */
    [[nodiscard]] crypto_scalar_t scalar() const;

    /**
     * Generates a vector of the individual bits within the hash without regard to the
     * endianness of the value by using the individual bytes represented in the hash
     * @param reversed
     * @return
     */
    [[nodiscard]] std::vector<unsigned char> to_bits(bool reversed = false) const;

    /**
     * Returns the hash as an uint256_t
     * @return
     */
    [[nodiscard]] uint256_t to_uint256_t() const;
};

#endif
