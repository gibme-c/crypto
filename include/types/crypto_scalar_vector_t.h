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

#ifndef CRYPTO_SCALAR_VECTOR_T
#define CRYPTO_SCALAR_VECTOR_T

#include <types/crypto_point_vector_t.h>

struct crypto_scalar_vector_t final : SerializableVector<crypto_scalar_t>
{
    crypto_scalar_vector_t() = default;

    explicit crypto_scalar_vector_t(std::vector<crypto_scalar_t> scalars);

    /**
     * Initializes the structure of the size count with the given value
     * @param size
     * @param value
     */
    explicit crypto_scalar_vector_t(size_t size, const crypto_scalar_t &value = Crypto::ZERO);

    /**
     * Adds the scalar to every value in the underlying container
     * @param other
     * @return
     */
    crypto_scalar_vector_t operator+(const crypto_scalar_t &other) const;

    /**
     * Adds the two vectors together and returns the resulting vector
     * @param other
     * @return
     */
    crypto_scalar_vector_t operator+(const crypto_scalar_vector_t &other) const;

    /**
     * Subtracts the scalar to every value in the underlying container
     * @param other
     * @return
     */
    crypto_scalar_vector_t operator-(const crypto_scalar_t &other) const;

    /**
     * Subtracts the second vector from the first vector and returns the results
     * @param other
     * @return
     */
    crypto_scalar_vector_t operator-(const crypto_scalar_vector_t &other) const;

    /**
     * Multiplies every value in the underlying container by the provided scalar and
     * returns the results
     * @param other
     * @return
     */
    crypto_scalar_vector_t operator*(const crypto_scalar_t &other) const;

    /**
     * Multiplies the vectors together and returns the results
     * Some call this a hadamard calculation
     * @param other
     * @return
     */
    crypto_scalar_vector_t operator*(const crypto_scalar_vector_t &other) const;

    /**
     * Multiplies the underlying vector of scalars by the vector of provided points
     * and returns the resulting points
     * @param other
     * @return
     */
    crypto_point_vector_t operator*(const crypto_point_vector_t &other) const;

    /**
     * Removes duplicates of the keys and sorts them by value
     * @return
     */
    [[nodiscard]] crypto_scalar_vector_t dedupe_sort() const;

    /**
     * Calculates the inner product of the two vectors
     * @param other
     * @return
     */
    [[nodiscard]] crypto_point_t inner_product(const crypto_point_vector_t &other) const;

    /**
     * Calculates the inner product of the two vectors
     * @param other
     * @return
     */
    [[nodiscard]] crypto_scalar_t inner_product(const crypto_scalar_vector_t &other) const;

    /**
     * Inverts each of the values in the underlying container such that (1/x)
     * @param allow_zero
     * @return
     */
    [[nodiscard]] crypto_scalar_vector_t invert(bool allow_zero = false) const;

    /**
     * Negates all of the values in the underlying container (0 - self)
     * @return
     */
    [[nodiscard]] crypto_scalar_vector_t negate() const;

    /**
     * Returns a slice of the underlying vector using the provided offsets
     * @param start
     * @param end
     * @return
     */
    [[nodiscard]] crypto_scalar_vector_t slice(size_t start, size_t end) const;

    /**
     * Adds all of the values in the underlying container together and returns the result
     * @return
     */
    [[nodiscard]] crypto_scalar_t sum() const;
};

#endif
