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

#ifndef CRYPTO_MATH_HELPERS_H
#define CRYPTO_MATH_HELPERS_H

#include <cstddef>
#include <cstdint>
#include <tuple>

namespace Crypto
{
    /**
     * Rounds @p value up to the next power of two (or returns it unchanged if already a power of two).
     *
     * @param value the input value
     * @return the smallest power of two >= @p value
     */
    inline size_t pow2_round(size_t value)
    {
        size_t count = 0;

        if (value && !(value & (value - 1)))
        {
            return value;
        }

        while (value != 0)
        {
            value >>= uint64_t(1);

            count++;
        }

        return uint64_t(1) << count;
    }

    /**
     * Finds the exponent e such that 2^e == @p target_value.
     *
     * Returns (true, e) if @p target_value is an exact power of two, or (false, 0) otherwise.
     * Handy when you need to verify that ring sizes or vector lengths are powers of two.
     *
     * @param target_value the value to test
     * @return (success, exponent) tuple
     */
    inline std::tuple<bool, size_t> calculate_base2_exponent(const size_t &target_value)
    {
        const auto rounded = pow2_round(target_value);

        if (rounded != target_value)
        {
            return {false, 0};
        }

        for (size_t exponent = 0; exponent < 63; ++exponent)
        {
            const auto val = size_t {1} << exponent;

            if (val == target_value)
            {
                return {true, exponent};
            }
        }

        return {false, 0};
    }
} // namespace Crypto

#endif // CRYPTO_MATH_HELPERS_H
