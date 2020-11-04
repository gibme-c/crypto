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
//
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

#ifndef CRYPTO_GRAY_CODE_GENERATOR_T
#define CRYPTO_GRAY_CODE_GENERATOR_T

#include <cstdint>
#include <types/crypto_scalar_t.h>
#include <vector>

struct gray_code_generator_t
{
    gray_code_generator_t(size_t N, size_t K, size_t v = -1);

    std::vector<int> operator[](int i) const;

    [[nodiscard]] size_t size() const;

    [[nodiscard]] std::vector<std::vector<int>> values() const;

    [[nodiscard]] std::vector<int> v_value() const;

  private:
    void generate();

    std::vector<std::vector<int>> changed;
    std::vector<int> v_changed;
    std::vector<int> g, u;
    size_t N = 0, K = 0, v = -1;
};

#endif
