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
 * @file crypto_config.h
 * @brief Compile-time configuration macros for the crypto library.
 *
 * All macros use `#ifndef` guards so you can override them by defining the macro before
 * including this header (or via `-D` compiler flags / CMake cache variables).
 */

#ifndef CRYPTO_CONFIG_H
#define CRYPTO_CONFIG_H

/**
 * @brief Number of bytes appended as a checksum in Base58-encoded addresses.
 *
 * A larger checksum reduces the chance of accepting a mistyped address but increases
 * the encoded string length. Default: 4 bytes (32-bit checksum).
 */
#ifndef CRYPTO_BASE58_CHECKSUM_SIZE
#define CRYPTO_BASE58_CHECKSUM_SIZE 4
#endif

/**
 * @brief Maximum accepted input length for Base58 / CNBase58 decode.
 *
 * Rationale: plain Base58 decode is O(n^2) in the
 * input length because every character triggers a carry-propagation loop
 * across the full working buffer, so a hostile caller who hands a decoder a
 * multi-megabyte string can pin a thread in an allocator + inner loop for an
 * arbitrarily long time. CNBase58 decode is O(n) but still allocates
 * proportional to the input with no upper bound. Both decoders are reached
 * from src/addresses/address_encoding.cpp via decode_check(), which in turn
 * is network-facing in downstream consumers. This cap bounds the worst-case
 * allocation and compute at the decode boundary, before any work happens.
 *
 * 4096 bytes is ~20x the longest legitimate encoded address this library
 * produces (a dual-key CNBase58 address with a varint prefix is on the order
 * of 190 characters), so the cap is never reached by well-formed input but
 * catches every realistic DoS payload. Override at compile time if an
 * exotic consumer needs a different upper bound.
 */
#ifndef CRYPTO_BASE58_MAX_INPUT_LENGTH
#define CRYPTO_BASE58_MAX_INPUT_LENGTH 4096
#endif

/**
 * @brief Earliest valid Unix timestamp for wallet seed creation dates.
 *
 * Seeds with a creation timestamp before this value are rejected as invalid.
 * Default: 1640995200 (2022-01-01 00:00:00 UTC).
 */
#ifndef CRYPTO_MINIMUM_SEED_TIMESTAMP
#define CRYPTO_MINIMUM_SEED_TIMESTAMP 1640995200
#endif

/**
 * @brief Latest valid Unix timestamp for wallet seed creation dates.
 *
 * Seeds with a creation timestamp after this value are rejected as invalid.
 * Default: 10413792000 (a far-future date).
 */
#ifndef CRYPTO_MAXIMUM_SEED_TIMESTAMP
#define CRYPTO_MAXIMUM_SEED_TIMESTAMP 10413792000
#endif

/**
 * @brief Default PBKDF2 iteration count for AES key derivation.
 *
 * Used by Crypto::AES::encrypt / Crypto::AES::decrypt with the
 * tinysha_pbkdf2_sha3_512 KDF. Higher values increase resistance to
 * offline brute-force / dictionary attacks at the cost of slower
 * encrypt/decrypt operations.
 *
 * Default: 220,000 iterations.
 *
 * Rationale: the OWASP Password Storage
 * Cheat Sheet (April 2026 revision) lists 220,000 as the floor for
 * PBKDF2-HMAC-SHA512. SHA3-512 is the correct OWASP-equivalent peer for
 * SHA-512 here: same 64-byte output, same "do more work per iteration"
 * cost profile that justifies OWASP's lower SHA-512 floor relative to
 * SHA-256 (600,000). In software SHA3-512 is in fact ~2x slower than
 * SHA-512 (no SHA3 hardware acceleration exists on commodity CPUs), so
 * 220,000 PBKDF2-HMAC-SHA3-512 iterations is, if anything, a slight
 * over-cost relative to the OWASP target — which is the conservative
 * direction.
 *
 * Wall-clock cost at 220,000 (PBKDF2-HMAC-SHA3-512):
 *   - Desktop x86 (no SHA3 HW accel):     ~0.4-0.5 s
 *   - Flagship phone (A17 / SD8G3 class): ~0.8-1.0 s
 *   - Midrange Android (~3 yr old):       ~1.7-2.0 s
 * This keeps wallet-unlock latency inside the user-tolerable band on
 * mobile, which is why we did not jump to PBKDF2-SHA256's 600,000 floor
 * (which would be ~5 s on midrange mobile for marginal extra bits).
 *
 * Revisit this number when:
 *   - The library migrates to a memory-hard KDF (Argon2id is already
 *     exposed via hash_t::argon2id but is not used here for mobile cost
 *     reasons), at which point the iteration count is replaced by
 *     {memory cost, time cost, parallelism} parameters.
 *   - SHA3 hardware acceleration becomes commonplace.
 *   - OWASP publishes an updated floor.
 */
#ifndef CRYPTO_PBKDF2_ITERATIONS
#define CRYPTO_PBKDF2_ITERATIONS 220000
#endif

/**
 * @brief Number of random bytes used to generate wallet entropy / seed material.
 *
 * Must be a multiple of 4 for BIP-0039 compatibility. Default: 32 (256-bit entropy,
 * corresponding to a 24-word mnemonic phrase).
 */
#ifndef CRYPTO_ENTROPY_BYTES
#define CRYPTO_ENTROPY_BYTES 32
#endif

/**
 * @name Benchmark Display Configuration
 * @brief Controls iteration counts and formatting for the benchmark binary.
 * @{
 */

/** @brief Base number of iterations for each benchmark measurement. Default: 1000. */
#ifndef BENCHMARK_PERFORMANCE_ITERATIONS
#define BENCHMARK_PERFORMANCE_ITERATIONS 1000
#endif

/**
 * @brief Multiplier applied to BENCHMARK_PERFORMANCE_ITERATIONS for fast operations
 * (hashing, encoding) that need more iterations to produce stable timings. Default: 60.
 */
#ifndef BENCHMARK_PERFORMANCE_ITERATIONS_LONG_MULTIPLIER
#define BENCHMARK_PERFORMANCE_ITERATIONS_LONG_MULTIPLIER 60
#endif

/** @brief Column width (in characters) for the benchmark label prefix. Default: 70. */
#ifndef BENCHMARK_PREFIX_WIDTH
#define BENCHMARK_PREFIX_WIDTH 70
#endif

/** @brief Column width (in characters) for each numeric result column. Default: 10. */
#ifndef BENCHMARK_COLUMN_WIDTH
#define BENCHMARK_COLUMN_WIDTH 10
#endif

/** @brief Decimal precision for benchmark timing output. Default: 3. */
#ifndef BENCHMARK_PRECISION
#define BENCHMARK_PRECISION 3
#endif

/** @} */

#endif
