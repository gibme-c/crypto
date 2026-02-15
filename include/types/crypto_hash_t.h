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

/**
 * @file crypto_hash_t.h
 * @brief 256-bit cryptographic hash type with multiple algorithm support and hash-to-curve operations.
 *
 * Provides a uniform 32-byte hash value that can be produced by SHA-3, SHA-256, SHA-384,
 * SHA-512, Blake2b, or Argon2 (d/i/id variants). Also includes the critical hash-to-point
 * and hash-to-scalar conversions used throughout the library's signature and proof systems.
 */

#ifndef CRYPTO_HASH_T
#define CRYPTO_HASH_T

#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * A 256-bit (32-byte) cryptographic hash value.
 *
 * This type is the workhorse for hashing throughout the library. Beyond plain hashing, it
 * provides conversions to scalars and curve points -- the building blocks for Fiat-Shamir
 * challenges, key images, and deterministic domain separation constants.
 */
struct crypto_hash_t final : SerializablePod<32>
{
    crypto_hash_t() = default;

    crypto_hash_t(std::initializer_list<unsigned char> input);

    explicit crypto_hash_t(const std::vector<unsigned char> &input);

    JSON_STRING_CONSTRUCTOR(crypto_hash_t, fromJSON)

    explicit crypto_hash_t(const char value[65]);

    /**
     * Hashes the given data with the given salt using Argon2d into a 256-bit hash.
     * Argon2d is data-dependent (memory access patterns depend on the input), making it
     * maximally GPU/ASIC-resistant but potentially vulnerable to side-channel attacks.
     * Best for non-interactive use cases like proof-of-work or key derivation where
     * side channels are not a concern.
     *
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @param salt pointer to the salt bytes
     * @param salt_length byte length of the salt
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2d hash
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
     * Hashes the given vector of data (using itself as salt) using Argon2d into a 256-bit hash.
     *
     * @tparam T element type of the input vector
     * @param input the data to hash (also used as its own salt)
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2d hash
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
     * Hashes the given data (using itself as salt) using Argon2d into a 256-bit hash.
     *
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash (also used as its own salt)
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2d hash
     */
    template<typename T>
    static crypto_hash_t
        argon2d(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return crypto_hash_t::argon2d(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data with the given salt using Argon2i into a 256-bit hash.
     * Argon2i is data-independent (memory access patterns are fixed), making it resistant
     * to side-channel attacks. Use this variant when the hashing environment may be shared
     * or observed (e.g., password hashing on multi-tenant servers).
     *
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @param salt pointer to the salt bytes
     * @param salt_length byte length of the salt
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2i hash
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
     * Hashes the given vector of data (using itself as salt) using Argon2i into a 256-bit hash.
     *
     * @tparam T element type of the input vector
     * @param input the data to hash (also used as its own salt)
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2i hash
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
     * Hashes the given data (using itself as salt) using Argon2i into a 256-bit hash.
     *
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash (also used as its own salt)
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2i hash
     */
    template<typename T>
    static crypto_hash_t
        argon2i(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return crypto_hash_t::argon2i(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data with the given salt using Argon2id into a 256-bit hash.
     * Argon2id is the recommended hybrid: the first pass is data-independent (side-channel
     * resistant like Argon2i), then subsequent passes are data-dependent (GPU-resistant
     * like Argon2d). This is the best general-purpose choice for password hashing.
     *
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @param salt pointer to the salt bytes
     * @param salt_length byte length of the salt
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2id hash
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
     * Hashes the given vector of data (using itself as salt) using Argon2id into a 256-bit hash.
     *
     * @tparam T element type of the input vector
     * @param input the data to hash (also used as its own salt)
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2id hash
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
     * Hashes the given data (using itself as salt) using Argon2id into a 256-bit hash.
     *
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash (also used as its own salt)
     * @param iterations number of iterations (time cost)
     * @param memory memory use in kilobytes
     * @param threads number of threads and compute lanes
     * @return the resulting 256-bit Argon2id hash
     */
    template<typename T>
    static crypto_hash_t
        argon2id(const T &input, const size_t iterations = 1, const size_t memory = 256, const size_t threads = 1)
    {
        return crypto_hash_t::argon2id(
            input.data(), input.size(), input.data(), input.size(), iterations, memory, threads);
    }

    /**
     * Hashes the given data using Blake2b into a 256-bit hash.
     *
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @return the resulting 256-bit Blake2b hash
     */
    static crypto_hash_t blake2b(const void *input, size_t length);

    /**
     * Hashes the given vector of data using Blake2b into a 256-bit hash.
     *
     * @tparam T element type of the input vector
     * @param input the data to hash
     * @return the resulting 256-bit Blake2b hash
     */
    template<typename T> static crypto_hash_t blake2b(const std::vector<T> &input)
    {
        return crypto_hash_t::blake2b(input.data(), input.size());
    }

    /**
     * Hashes the given data using Blake2b into a 256-bit hash.
     *
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash
     * @return the resulting 256-bit Blake2b hash
     */
    template<typename T> static crypto_hash_t blake2b(const T &input)
    {
        return crypto_hash_t::blake2b(input.data(), input.size());
    }

    /**
     * Counts leading zero hex characters in the hash string. Useful for proof-of-work
     * difficulty checks where you need the hash to start with a certain number of zeros.
     * @param reversed if true, count from the end of the hex string instead
     * @return number of leading zero hex characters
     */
    [[nodiscard]] size_t hex_leading_zeros(bool reversed = false) const;

    /**
     * Generates a random 256-bit hash from cryptographically secure random bytes.
     * @return a random hash value
     */
    [[nodiscard]] static crypto_hash_t random();

    /**
     * Generates a vector of random hashes.
     * @param count how many random hashes to generate
     * @return vector of independently sampled random hashes
     */
    [[nodiscard]] static std::vector<crypto_hash_t> random(size_t count);

    /**
     * Hashes the given input data using SHA-3 (Keccak-256) into a 256-bit hash. This is the
     * primary hash function used throughout the library for Fiat-Shamir challenges, key
     * derivation, and transcript hashing.
     *
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @return the resulting 256-bit SHA-3 hash
     */
    static crypto_hash_t sha3(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-3 (Keccak-256) into a 256-bit hash.
     *
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash
     * @return the resulting 256-bit SHA-3 hash
     */
    template<typename T> static crypto_hash_t sha3(const T &input)
    {
        return sha3(input.data(), input.size());
    }

    /**
     * Iterated SHA-3 with key stretching for deterministic domain separation.
     *
     * Each round appends the original input to the previous hash before re-hashing, so
     * the result depends on both the input and the iteration count. This is used internally
     * to generate the library's domain separation constants (salt scalars/points) -- NOT
     * intended as a password hashing replacement (use Argon2 for that).
     *
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @param iterations number of SHA-3 stretching rounds
     * @return the resulting stretched 256-bit hash
     */
    static crypto_hash_t sha3_slow(const void *input, size_t length, uint64_t iterations);

    /**
     * Iterated SHA-3 with key stretching (POD/string overload). See the raw-pointer
     * overload for details on what "slow" means here.
     *
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash
     * @param iterations number of SHA-3 stretching rounds (0 = single hash)
     * @return the resulting stretched 256-bit hash
     */
    template<typename T> static crypto_hash_t sha3_slow(const T &input, uint64_t iterations = 0)
    {
        return sha3_slow(input.data(), input.size(), iterations);
    }

    /**
     * Hashes the given input data using SHA-256 into a 256-bit hash.
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @return the resulting 256-bit SHA-256 hash
     */
    static crypto_hash_t sha256(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-256 into a 256-bit hash.
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash
     * @return the resulting 256-bit SHA-256 hash
     */
    template<typename T> static crypto_hash_t sha256(const T &input)
    {
        return sha256(input.data(), input.size());
    }

    /**
     * Hashes the given input data using SHA-384 (truncated to 256 bits) into a 256-bit hash.
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @return the resulting 256-bit truncated SHA-384 hash
     */
    static crypto_hash_t sha384(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-384 (truncated to 256 bits) into a 256-bit hash.
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash
     * @return the resulting 256-bit truncated SHA-384 hash
     */
    template<typename T> static crypto_hash_t sha384(const T &input)
    {
        return sha384(input.data(), input.size());
    }

    /**
     * Hashes the given input data using SHA-512 (truncated to 256 bits) into a 256-bit hash.
     * @param input pointer to the data to hash
     * @param length byte length of the input data
     * @return the resulting 256-bit truncated SHA-512 hash
     */
    static crypto_hash_t sha512(const void *input, size_t length);

    /**
     * Hashes the given input data using SHA-512 (truncated to 256 bits) into a 256-bit hash.
     * @tparam T input type (must have .data() and .size())
     * @param input the data to hash
     * @return the resulting 256-bit truncated SHA-512 hash
     */
    template<typename T> static crypto_hash_t sha512(const T &input)
    {
        return sha512(input.data(), input.size());
    }

    /**
     * Counts leading zero bits in the hash. Like hex_leading_zeros() but at bit granularity,
     * giving finer difficulty resolution for proof-of-work checks.
     * @param reversed if true (default), count from the high bits; if false, from the low bits
     * @return number of leading zero bits
     */
    [[nodiscard]] size_t leading_zeros(bool reversed = true) const;

    /**
     * Hash-to-point: deterministically maps this hash to an Ed25519 curve point. This is a
     * critical operation used to generate key images (which must be unique per secret key)
     * and to derive generator points for ring signatures and proofs.
     * @return a curve point deterministically derived from the hash bytes
     */
    [[nodiscard]] crypto_point_t point() const;

    /**
     * Hash-to-scalar: reduces the hash bytes modulo l to produce a canonical scalar. Used
     * extensively for Fiat-Shamir challenge generation in non-interactive proofs and signatures.
     * @return a scalar in [0, l) derived from the hash bytes
     */
    [[nodiscard]] crypto_scalar_t scalar() const;

    /**
     * Decomposes the hash into individual bits (as bytes, each 0 or 1), processing bytes
     * in storage order without endianness conversion.
     * @param reversed if true, reverse the bit order
     * @return vector of 256 bytes, each representing one bit of the hash
     */
    [[nodiscard]] std::vector<unsigned char> to_bits(bool reversed = false) const;

    /**
     * Returns the hash bytes interpreted as a 256-bit unsigned integer.
     * @return the hash as a uint256_t
     */
    [[nodiscard]] uint256_t to_uint256_t() const;
};

#endif
