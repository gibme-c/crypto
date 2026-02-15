// Copyright (c) 2017, Daan Sprenkels <hello@dsprenkels.com>
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
 * @file random_bytes.h
 * @brief Cryptographically secure pseudorandom number generator (CSPRNG).
 *
 * Provides a simple C-compatible interface for filling a buffer with high-quality
 * random bytes sourced from the operating system's entropy pool (e.g., BCryptGenRandom
 * on Windows, /dev/urandom on Linux). Used throughout the library for nonce generation,
 * blinding factors, and key generation.
 */

#ifndef CRYPTO_RANDOM_BYTES_H
#define CRYPTO_RANDOM_BYTES_H

#include <random>

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef _WIN32
/* Load size_t on windows */
#include <crtdefs.h>
#else
#include <unistd.h>
#endif /* _WIN32 */


    /**
     * Fills a buffer with cryptographically secure random bytes.
     *
     * @param n the number of random bytes to generate
     * @param buf pointer to the output buffer (must be at least n bytes)
     * @return 0 on success, non-zero on failure
     */
    int random_bytes(size_t n, void *buf);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_RANDOM_BYTES_H
