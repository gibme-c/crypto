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
 * @file wide_reduction.h
 * @brief SHA-512 wide-hash reduction for RFC 8032 Ed25519 signatures.
 *
 * Reduces a 512-bit SHA-512 digest into an Ed25519 scalar without bias by splitting
 * the 64-byte input into three limbs and reconstructing as a + b*2^168 + c*2^336.
 * Used by both solo and threshold RFC 8032 signature generation.
 */

#ifndef CRYPTO_HELPERS_WIDE_REDUCTION_H
#define CRYPTO_HELPERS_WIDE_REDUCTION_H

#include <types/scalar_t.h>
#include <vector>

namespace Crypto
{
    /**
     * Load a sub-range of a 64-byte buffer into a 32-byte scalar (zero-padded on the right).
     *
     * @param input 64-byte SHA-512 digest
     * @param start byte offset to begin reading
     * @param end byte offset to stop reading (exclusive)
     * @return the loaded scalar
     */
    inline scalar_t load_partial_scalar(const unsigned char input[64], size_t start, size_t end)
    {
        std::vector<unsigned char> temp(32, 0);

        std::copy(input + start, input + end, temp.begin());

        return scalar_t(temp);
    }

    namespace detail
    {
        inline const scalar_t &pow2_168()
        {
            static const auto value = Crypto::TWO.pow(168);
            return value;
        }

        inline const scalar_t &pow2_336()
        {
            static const auto value = Crypto::TWO.pow(336);
            return value;
        }
    } // namespace detail

    /**
     * Reduce a 512-bit SHA-512 digest into a scalar: split into three limbs and
     * reconstruct as a + b*2^168 + c*2^336 to avoid bias from naive modular reduction.
     *
     * @param input 64-byte SHA-512 digest
     * @return the reduced scalar
     */
    inline scalar_t reduce_wide_hash(const unsigned char input[64])
    {
        const auto a = load_partial_scalar(input, 0, 21);

        const auto b = load_partial_scalar(input, 21, 42);

        const auto c = load_partial_scalar(input, 42, 64);

        return a + (b * detail::pow2_168()) + (c * detail::pow2_336());
    }
} // namespace Crypto

#endif
