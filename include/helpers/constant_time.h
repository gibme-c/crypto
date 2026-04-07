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
 * @file constant_time.h
 * @brief Constant-time comparison to prevent timing side-channel attacks.
 *
 * When comparing secret data (like keys, MACs, or signatures), a naive byte-by-byte
 * comparison that short-circuits on the first mismatch leaks information about how
 * many leading bytes match. This function always examines every byte, taking the same
 * amount of time regardless of where (or whether) the inputs differ.
 */

#ifndef CRYPTO_CONSTANT_TIME_H
#define CRYPTO_CONSTANT_TIME_H

#include <cstddef>

/**
 * Compares two byte buffers in constant time.
 *
 * Always reads all `len` bytes from both buffers, accumulating differences via XOR.
 * The result reveals only whether the buffers are equal -- not where they differ.
 *
 * @param a pointer to the first buffer
 * @param b pointer to the second buffer
 * @param len the number of bytes to compare
 * @return true if all bytes are identical, false otherwise
 */
static inline bool constant_time_equals(const void *a, const void *b, size_t len)
{
    const auto *x = static_cast<const unsigned char *>(a);
    const auto *y = static_cast<const unsigned char *>(b);
    unsigned char result = 0;

    for (size_t i = 0; i < len; i++)
    {
        result |= x[i] ^ y[i];
    }

    return result == 0;
}

/**
 * Constant-time conditional select: returns @p true_val if @p condition is true,
 * @p false_val otherwise, without branching.
 *
 * @param condition the boolean selector
 * @param true_val value returned when condition is true
 * @param false_val value returned when condition is false
 * @return the selected value
 */
static inline size_t constant_time_select(bool condition, size_t true_val, size_t false_val)
{
    const size_t mask = static_cast<size_t>(-static_cast<ptrdiff_t>(condition));
    return (true_val & mask) | (false_val & ~mask);
}

#endif // CRYPTO_CONSTANT_TIME_H
