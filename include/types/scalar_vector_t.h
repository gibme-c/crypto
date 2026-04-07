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
 * @file scalar_vector_t.h
 * @brief Vector of Ed25519 scalars with batch arithmetic, inner products, and Hadamard operations.
 *
 * This is the workhorse type for Bulletproofs and other zero-knowledge proof systems. It provides
 * element-wise arithmetic, scalar-point multiplication against point vectors, inner products (both
 * scalar-scalar and scalar-point), batch modular inversion, and utility methods like slicing and
 * power expansion. Most of the heavy computation in an inner product argument boils down to
 * operations on scalar vectors.
 */

#ifndef SCALAR_VECTOR_T_H
#define SCALAR_VECTOR_T_H

#include <types/point_vector_t.h>

/**
 * @brief A vector of Ed25519 scalars with batch arithmetic and algebraic operations.
 *
 * Supports element-wise addition, subtraction, and multiplication (Hadamard product),
 * scalar broadcasting, inner products against both scalar and point vectors, batch
 * modular inversion, and slicing. These are the core primitives used in the inner
 * product argument of Bulletproofs, where you repeatedly fold, combine, and reduce
 * scalar vectors with challenge values.
 */
struct scalar_vector_t final : SerializableVector<scalar_t>
{
    scalar_vector_t() = default;

    explicit scalar_vector_t(std::vector<scalar_t> scalars);

    /**
     * Constructs a vector of the given size, with every element set to @p value.
     * @param size the number of elements
     * @param value the scalar to fill with (defaults to zero)
     */
    explicit scalar_vector_t(size_t size, const scalar_t &value = Crypto::ZERO);

    /**
     * Broadcast addition: result[i] = this[i] + other for every element.
     * @param other the scalar to add to each element
     * @return a new vector with the scalar added to every element
     */
    scalar_vector_t operator+(const scalar_t &other) const;

    /**
     * Element-wise addition: result[i] = this[i] + other[i].
     * @param other the scalar vector to add (must be the same length)
     * @return a new vector containing the element-wise sums
     */
    scalar_vector_t operator+(const scalar_vector_t &other) const;

    /**
     * Broadcast subtraction: result[i] = this[i] - other for every element.
     * @param other the scalar to subtract from each element
     * @return a new vector with the scalar subtracted from every element
     */
    scalar_vector_t operator-(const scalar_t &other) const;

    /**
     * Element-wise subtraction: result[i] = this[i] - other[i].
     * @param other the scalar vector to subtract (must be the same length)
     * @return a new vector containing the element-wise differences
     */
    scalar_vector_t operator-(const scalar_vector_t &other) const;

    /**
     * Broadcast scalar multiplication: result[i] = this[i] * other for every element.
     * @param other the scalar to multiply each element by
     * @return a new vector of scaled values
     */
    scalar_vector_t operator*(const scalar_t &other) const;

    /**
     * Hadamard product (element-wise multiplication): result[i] = this[i] * other[i].
     *
     * Not to be confused with inner_product(), which sums the element-wise products
     * into a single scalar. The Hadamard product keeps them as a vector.
     *
     * @param other the scalar vector to multiply with (must be the same length)
     * @return a new vector of element-wise products
     */
    scalar_vector_t operator*(const scalar_vector_t &other) const;

    /**
     * Multi-scalar multiplication: result[i] = this[i] * other[i] (scalar-point product).
     *
     * Computes the scalar-point multiplication for each pair of elements. This is one of the
     * most expensive operations in proof systems and benefits from multi-scalar multiplication
     * (MSM) optimizations under the hood.
     *
     * @param other the point vector to multiply against (must be the same length)
     * @return a new point vector of the scalar-point products
     */
    point_vector_t operator*(const point_vector_t &other) const;

    /**
     * Removes duplicate scalars and sorts them by their byte representation.
     * @return a new vector with duplicates removed and elements sorted
     */
    [[nodiscard]] scalar_vector_t dedupe_sort() const;

    /**
     * Scalar-point inner product: result = sum(this[i] * other[i]) for all i.
     *
     * This is the multi-scalar multiplication (MSM) that produces a single curve point.
     * It is the core operation in the Bulletproofs inner product argument, where you compute
     * linear combinations of generator points weighted by scalar coefficients.
     *
     * @param other the point vector to combine with (must be the same length)
     * @return a single curve point equal to the sum of element-wise scalar-point products
     */
    [[nodiscard]] point_t inner_product(const point_vector_t &other) const;

    /**
     * Scalar-scalar inner product: result = sum(this[i] * other[i]) for all i.
     *
     * Computes the dot product of two scalar vectors, returning a single scalar. This is
     * used in Bulletproofs to compute the inner product value t = <l, r> that the prover
     * commits to.
     *
     * @param other the scalar vector to dot with (must be the same length)
     * @return a single scalar equal to the sum of element-wise products
     */
    [[nodiscard]] scalar_t inner_product(const scalar_vector_t &other) const;

    /**
     * Batch modular inversion: result[i] = 1 / this[i] (mod l).
     *
     * Uses Montgomery's trick to compute all inversions with a single expensive modular
     * inverse plus O(n) multiplications, making it dramatically faster than inverting each
     * element individually. This is heavily used in Bulletproofs verification.
     *
     * @param allow_zero if true, zero elements are left as zero instead of throwing
     * @return a new vector where each element is the modular inverse of the original
     */
    [[nodiscard]] scalar_vector_t invert(bool allow_zero = false) const;

    /**
     * Negates every scalar: result[i] = -this[i] (mod l).
     * @return a new vector of negated scalars
     */
    [[nodiscard]] scalar_vector_t negate() const;

    /**
     * Returns a contiguous sub-range of the vector as a new vector.
     * @param start the starting index (inclusive)
     * @param end the ending index (exclusive)
     * @return a new vector containing elements [start, end)
     */
    [[nodiscard]] scalar_vector_t slice(size_t start, size_t end) const;

    /**
     * Adds all scalars together: result = this[0] + this[1] + ... + this[n-1].
     * @return the aggregate sum as a single scalar
     */
    [[nodiscard]] scalar_t sum() const;
};

#endif
