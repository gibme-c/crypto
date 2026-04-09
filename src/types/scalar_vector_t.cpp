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
 * @file scalar_vector_t.cpp
 * @brief Scalar vector operations: Hadamard product, inner products, batch inversion via Montgomery's trick, slicing.
 */

#include <cstring>
#include <helpers/dedupe_and_sort_keys.h>
#include <types/scalar_vector_t.h>
#include <utility>

scalar_vector_t::scalar_vector_t(std::vector<scalar_t> scalars)
{
    container = std::move(scalars);
}

scalar_vector_t::scalar_vector_t(size_t size, const scalar_t &value)
{
    container = std::vector<scalar_t>(size, value);
}

scalar_vector_t scalar_vector_t::operator+(const scalar_t &other) const
{
    std::vector<scalar_t> result(container);

    for (auto &val : result)
    {
        val += other;
    }

    return scalar_vector_t(result);
}

scalar_vector_t scalar_vector_t::operator+(const scalar_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        // Malformed-input contract.
        throw std::invalid_argument("vectors must be of the same size");
    }

    std::vector<scalar_t> result(container);

    for (size_t i = 0; i < result.size(); ++i)
    {
        result[i] += other.container[i];
    }

    return scalar_vector_t(result);
}

scalar_vector_t scalar_vector_t::operator-(const scalar_t &other) const
{
    std::vector<scalar_t> result(container);

    for (auto &val : result)
    {
        val -= other;
    }

    return scalar_vector_t(result);
}

scalar_vector_t scalar_vector_t::operator-(const scalar_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        // Malformed-input contract.
        throw std::invalid_argument("vectors must be of the same size");
    }

    std::vector<scalar_t> result(container);

    for (size_t i = 0; i < result.size(); ++i)
    {
        result[i] -= other.container[i];
    }

    return scalar_vector_t(result);
}

scalar_vector_t scalar_vector_t::operator*(const scalar_t &other) const
{
    std::vector<scalar_t> result(container);

    for (auto &val : result)
    {
        val *= other;
    }

    return scalar_vector_t(result);
}

scalar_vector_t scalar_vector_t::operator*(const scalar_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        // Malformed-input contract.
        throw std::invalid_argument("vectors must be of the same size");
    }

    std::vector<scalar_t> result(container);

    for (size_t i = 0; i < result.size(); ++i)
    {
        result[i] *= other.container[i];
    }

    return scalar_vector_t(result);
}

point_vector_t scalar_vector_t::operator*(const point_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        // Malformed-input contract.
        throw std::invalid_argument("vectors must be of the same size");
    }

    std::vector<point_t> result(container.size());

    for (size_t i = 0; i < result.size(); ++i)
    {
        result[i] = container[i] * other.container[i];
    }

    return point_vector_t(result);
}

scalar_vector_t scalar_vector_t::dedupe_sort() const
{
    return scalar_vector_t(dedupe_and_sort_keys(container));
}

point_t scalar_vector_t::inner_product(const point_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        // Malformed-input contract.
        throw std::invalid_argument("vectors must be of equal size");
    }

    const auto n = container.size();

    /**
     * If there is only a single value in each vector then it is faster
     * to just compute the result of the multiplication
     */
    if (n == 1)
    {
        return container[0] * other[0];
    }

    /**
     * Use multi-scalar multiplication (MSM) to compute the sum of all
     * scalar*point products in a single batched call. This replaces
     * the previous approach of n/2 dbl_mult calls followed by a
     * sequential summation, giving roughly log2(n) speedup via
     * Straus (n<=32) or Pippenger (n>32) algorithms.
     */
    std::vector<unsigned char> scalars(n * 32);
    std::vector<ge_p3> points(n);

    for (size_t i = 0; i < n; ++i)
    {
        std::memcpy(&scalars[i * 32], container[i].data(), 32);
        points[i] = other[i].p3();
    }

    ge_p3 result; // NOLINT: immediately populated by ge_multiscalar_mul
    ge_multiscalar_mul_vartime(&result, scalars.data(), points.data(), n);

    return point_t(result);
}

scalar_t scalar_vector_t::inner_product(const scalar_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        // Malformed-input contract.
        throw std::invalid_argument("vectors must be of equal size");
    }

    return (*this * other).sum();
}

scalar_vector_t scalar_vector_t::invert(bool allow_zero) const
{
    if (allow_zero)
    {
        // Simple per-element inversion; zeros invert to zero
        std::vector<scalar_t> result(container);

        for (auto &scalar : result)
        {
            scalar = scalar.invert();
        }

        return scalar_vector_t(result);
    }
    else
    {
        // Montgomery's trick: compute n inversions using only 1 field inversion
        // plus 3(n-1) multiplications, rather than n independent inversions.
        auto inputs = container;

        const auto n = inputs.size();

        // scratch[i] holds the running product of inputs[0..i-1]
        std::vector<scalar_t> scratch(n, Crypto::ONE);

        // Forward pass: accumulate prefix products
        auto acc = Crypto::ONE;

        for (size_t i = 0; i < n; ++i)
        {
            if (inputs[i].empty())
            {
                // Malformed-input contract.
                throw std::invalid_argument("scalar_vector_t::invert: cannot divide by 0");
            }

            scratch[i] = acc;

            acc *= inputs[i];
        }

        // Single inversion of the full product
        acc = acc.invert();

        // Backward pass: extract individual inverses from the accumulated inverse
        for (size_t i = n; i-- > 0;)
        {
            auto temp = acc * inputs[i];

            inputs[i] = acc * scratch[i];

            acc = temp;
        }

        return scalar_vector_t(inputs);
    }
}

scalar_vector_t scalar_vector_t::negate() const
{
    std::vector<scalar_t> result(container);

    for (auto &scalar : result)
    {
        scalar = scalar.negate();
    }

    return scalar_vector_t(result);
}

scalar_vector_t scalar_vector_t::slice(size_t start, size_t end) const
{
    if (end < start)
    {
        // Malformed-input contract.
        throw std::invalid_argument("ending offset must be greater than or equal to starting offset");
    }

    if (start > container.size() || end > container.size())
    {
        // Malformed-input contract.
        throw std::invalid_argument("slice bounds exceed vector size");
    }

    return scalar_vector_t(std::vector<scalar_t>(container.begin() + start, container.begin() + end));
}

scalar_t scalar_vector_t::sum() const
{
    auto result = Crypto::ZERO;

    for (const auto &scalar : container)
    {
        result += scalar;
    }

    return result;
}
