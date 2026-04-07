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
 * @file gray_code_generator_t.cpp
 * @brief N-ary Gray code generator for Triptych signature optimizations.
 */

// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

#include <helpers/gray_code_generator_t.h>

gray_code_generator_t::gray_code_generator_t(size_t _N, size_t _K, size_t _v): N(_N), K(_K), v(_v)
{
    g = std::vector<int>(K + 1, 0);

    u = std::vector<int>(K + 1, 1);

    changed.resize(1);

    changed[0] = {0, 0, 0};

    generate();
}

std::vector<int> gray_code_generator_t::operator[](int i) const
{
    return changed[i];
}

// Generates all N^K - 1 transitions of the N-ary Gray code.
// Each transition records {position, old_digit, new_digit} so that
// Triptych can incrementally update commitment sums per-position.
void gray_code_generator_t::generate()
{
    const auto upper = size_t(scalar_t(N).pow(K).to_uint64_t()) - 1;

    for (size_t idx = 0; idx < upper; ++idx)
    {
        // Snapshot the digit vector at the signer's index
        if (idx == v)
        {
            v_changed = std::vector<int>(g.begin(), g.end() - 1);
        }

        // Find the lowest position whose digit can be incremented/decremented
        int i = 0, k = g[0] + u[0];

        while (k >= static_cast<int>(N) || k < 0)
        {
            u[i] = u[i] * -1;

            i += 1;

            k = g[i] + u[i];
        }

        changed.push_back({i, g[i], k});

        g[i] = k;
    }
}

size_t gray_code_generator_t::size() const
{
    return changed.size();
}

std::vector<std::vector<int>> gray_code_generator_t::values() const
{
    return changed;
}

std::vector<int> gray_code_generator_t::v_value() const
{
    return v_changed;
}
