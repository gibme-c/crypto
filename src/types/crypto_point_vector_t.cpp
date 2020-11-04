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

#include <helpers/dedupe_and_sort_keys.h>
#include <types/crypto_point_vector_t.h>
#include <utility>

crypto_point_vector_t::crypto_point_vector_t(std::vector<crypto_point_t> points)
{
    container = std::move(points);
}

crypto_point_vector_t::crypto_point_vector_t(size_t size, const crypto_point_t &value)
{
    container = std::vector<crypto_point_t>(size, value);
}

crypto_point_vector_t crypto_point_vector_t::operator+(const crypto_point_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        throw std::range_error("vectors must be of the same size");
    }

    std::vector<crypto_point_t> result(container);

    for (size_t i = 0; i < result.size(); ++i)
    {
        result[i] += other.container[i];
    }

    return crypto_point_vector_t(result);
}

crypto_point_vector_t crypto_point_vector_t::operator-(const crypto_point_vector_t &other) const
{
    if (container.size() != other.container.size())
    {
        throw std::range_error("vectors must be of the same size");
    }

    std::vector<crypto_point_t> result(container);

    for (size_t i = 0; i < result.size(); ++i)
    {
        result[i] -= other.container[i];
    }

    return crypto_point_vector_t(result);
}

crypto_point_vector_t crypto_point_vector_t::operator*(const crypto_scalar_t &other) const
{
    std::vector<crypto_point_t> result(container);

    for (auto &point : result)
    {
        point = other * point;
    }

    return crypto_point_vector_t(result);
}

crypto_point_vector_t crypto_point_vector_t::dbl_mult(
    const crypto_scalar_t &a,
    const crypto_point_vector_t &B,
    const crypto_scalar_t &b) const
{
    if (container.size() != B.size())
    {
        throw std::invalid_argument("vectors must be of the same size");
    }

    std::vector<crypto_point_t> result(container.size());

    for (size_t i = 0; i < container.size(); ++i)
    {
        result[i] = a.dbl_mult(container[i], b, B.container[i]);
    }

    return crypto_point_vector_t(result);
}

crypto_point_vector_t crypto_point_vector_t::dedupe_sort() const
{
    return crypto_point_vector_t(dedupe_and_sort_keys(container));
}

crypto_point_vector_t crypto_point_vector_t::negate() const
{
    std::vector<crypto_point_t> result(container);

    for (auto &point : result)
    {
        point = point.negate();
    }

    return crypto_point_vector_t(result);
}

crypto_point_vector_t crypto_point_vector_t::slice(size_t start, size_t end) const
{
    if (end < start)
    {
        throw std::range_error("ending offset must be greater than or equal to starting offset");
    }

    return crypto_point_vector_t(std::vector<crypto_point_t>(container.begin() + start, container.begin() + end));
}

crypto_point_t crypto_point_vector_t::sum() const
{
    auto result = Crypto::Z;

    for (const auto &point : container)
    {
        result += point;
    }

    return result;
}
