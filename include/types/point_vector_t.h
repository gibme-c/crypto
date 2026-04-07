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
 * @file point_vector_t.h
 * @brief Vector of Ed25519 curve points with batch arithmetic operations.
 *
 * Provides element-wise and aggregate operations over collections of curve points,
 * including batch addition, scalar multiplication, double-scalar multiplication, and
 * summation. These batch operations are the building blocks for zero-knowledge proof
 * systems (e.g., the inner product argument in Bulletproofs) where you frequently need
 * to compute linear combinations of large point vectors.
 */

#ifndef POINT_VECTOR_T_H
#define POINT_VECTOR_T_H

#include <types/point_t.h>
#include <types/scalar_t.h>

/**
 * @brief A vector of Ed25519 curve points with element-wise and aggregate arithmetic.
 *
 * Wraps a `std::vector<point_t>` and adds operator overloads for point-wise
 * addition, subtraction, scalar multiplication, and double-scalar multiplication. Also
 * provides utility methods like `sum()`, `negate()`, `slice()`, and `dedupe_sort()`.
 *
 * These operations show up constantly in range proof and inner product argument
 * computations, where you need to fold, combine, or reduce vectors of generator points.
 */
struct point_vector_t final : SerializableVector<point_t>
{
    point_vector_t() = default;

    explicit point_vector_t(std::vector<point_t> points);

    /**
     * Constructs a vector of the given size, with every element set to @p value.
     * @param size the number of elements
     * @param value the point to fill with (defaults to the identity point Z)
     */
    explicit point_vector_t(size_t size, const point_t &value = Crypto::Z);

    /**
     * Element-wise point addition: result[i] = this[i] + other[i].
     * @param other the point vector to add (must be the same length)
     * @return a new vector containing the element-wise sums
     */
    point_vector_t operator+(const point_vector_t &other) const;

    /**
     * Element-wise point subtraction: result[i] = this[i] - other[i].
     * @param other the point vector to subtract (must be the same length)
     * @return a new vector containing the element-wise differences
     */
    point_vector_t operator-(const point_vector_t &other) const;

    /**
     * Scalar multiplication of every point in the vector: result[i] = other * this[i].
     * @param other the scalar to multiply each point by
     * @return a new vector of scaled points
     */
    point_vector_t operator*(const scalar_t &other) const;

    /**
     * Double-scalar multiplication: result[i] = a * this[i] + b * B[i].
     *
     * Computes both scalar-point products and their sum in a single pass for each element,
     * which is more efficient than doing them separately. This pattern appears in inner
     * product argument folding, where generator vectors are combined with challenge scalars.
     *
     * @param a scalar applied to each element of this vector
     * @param B second point vector (must be the same length as this)
     * @param b scalar applied to each element of B
     * @return a new vector of the combined results
     */
    [[nodiscard]] point_vector_t dbl_mult(const scalar_t &a, const point_vector_t &B, const scalar_t &b) const;

    /**
     * Removes duplicate points and sorts them by their byte representation.
     * @return a new vector with duplicates removed and elements sorted
     */
    [[nodiscard]] point_vector_t dedupe_sort() const;

    /**
     * Negates every point in the vector: result[i] = -this[i] (the additive inverse on the curve).
     * @return a new vector of negated points
     */
    [[nodiscard]] point_vector_t negate() const;

    /**
     * Returns a contiguous sub-range of the vector as a new vector.
     * @param start the starting index (inclusive)
     * @param end the ending index (exclusive)
     * @return a new vector containing elements [start, end)
     */
    [[nodiscard]] point_vector_t slice(size_t start, size_t end) const;

    /**
     * Adds all points in the vector together: result = this[0] + this[1] + ... + this[n-1].
     * @return the aggregate sum as a single curve point
     */
    [[nodiscard]] point_t sum() const;
};

#endif
