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

/**
 * @file gray_code_generator_t.h
 * @brief Gray code sequence generator for Triptych ring signatures.
 *
 * A Gray code is a binary numeral system where consecutive values differ by exactly
 * one bit. This is used in Triptych signature construction to efficiently walk through
 * matrix index permutations, enabling incremental updates instead of full recomputation
 * at each step.
 */

#ifndef CRYPTO_GRAY_CODE_GENERATOR_T
#define CRYPTO_GRAY_CODE_GENERATOR_T

#include <cstdint>
#include <types/crypto_scalar_t.h>
#include <vector>

/**
 * @brief Generates Gray code sequences for efficient matrix traversal in Triptych proofs.
 *
 * Constructed with dimensions N (base) and K (digits), it precomputes the sequence of
 * bit-position changes so that Triptych signing can update its accumulators incrementally.
 */
struct gray_code_generator_t
{
    /**
     * Constructs the Gray code generator and precomputes the sequence.
     *
     * @param N the base (number of values per digit position)
     * @param K the number of digit positions
     * @param v optional starting value (defaults to max, i.e., wraps around)
     */
    gray_code_generator_t(size_t N, size_t K, size_t v = -1);

    /**
     * Returns the list of changed digit positions at step i.
     *
     * @param i the step index
     * @return the digit positions that changed at this step
     */
    std::vector<int> operator[](int i) const;

    /**
     * Returns the total number of steps in the Gray code sequence.
     *
     * @return the sequence length (N^K)
     */
    [[nodiscard]] size_t size() const;

    /**
     * Returns all change vectors for the entire sequence.
     *
     * @return a vector of change vectors, one per step
     */
    [[nodiscard]] std::vector<std::vector<int>> values() const;

    /**
     * Returns the direction-change vector used during generation.
     *
     * @return the v-value vector
     */
    [[nodiscard]] std::vector<int> v_value() const;

  private:
    void generate();

    std::vector<std::vector<int>> changed;
    std::vector<int> v_changed;
    std::vector<int> g, u;
    size_t N = 0, K = 0, v = -1;
};

#endif
