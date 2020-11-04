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

#include <cryptopp/sha.h>
#include <types/crypto_secret_key_t.h>

crypto_secret_key_t::crypto_secret_key_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

crypto_secret_key_t::crypto_secret_key_t(const std::vector<unsigned char> &input)
{
    if (input.size() != sizeof(bytes))
    {
        throw std::runtime_error("could not load secret key");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

crypto_secret_key_t::crypto_secret_key_t(const std::string &s)
{
    from_string(s);

    load_hook();
}

crypto_secret_key_t::operator crypto_scalar_t() const
{
    return scalar();
}

bool crypto_secret_key_t::operator==(const crypto_secret_key_t &other) const
{
    return std::equal(std::begin(bytes), std::end(bytes), std::begin(other.bytes));
}

bool crypto_secret_key_t::operator!=(const crypto_secret_key_t &other) const
{
    return !(*this == other);
}

bool crypto_secret_key_t::operator<(const crypto_secret_key_t &other) const
{
    for (size_t i = sizeof(bytes); i-- > 0;)
    {
        if (bytes[i] < other.bytes[i])
        {
            return true;
        }

        if (bytes[i] > other.bytes[i])
        {
            return false;
        }
    }

    return false;
}

bool crypto_secret_key_t::operator<=(const crypto_secret_key_t &other) const
{
    return (*this < other) || (*this == other);
}

bool crypto_secret_key_t::operator>(const crypto_secret_key_t &other) const
{
    for (size_t i = sizeof(bytes); i-- > 0;)
    {
        if (bytes[i] > other.bytes[i])
        {
            return true;
        }

        if (bytes[i] < other.bytes[i])
        {
            return false;
        }
    }

    return false;
}

bool crypto_secret_key_t::operator>=(const crypto_secret_key_t &other) const
{
    return (*this > other) || (*this == other);
}

crypto_scalar_t crypto_secret_key_t::scalar() const
{
    return _scalar;
}

crypto_point_t crypto_secret_key_t::point() const
{
    return _scalar.point();
}

void crypto_secret_key_t::load_hook()
{
    std::vector<unsigned char> hash(64);

    const auto hash_context = new CryptoPP::SHA512();

    hash_context->Update(bytes, sizeof(bytes));

    hash_context->Final(hash.data());

    free(hash_context);

    hash.resize(32); // truncate the hash to 32-bytes

    _scalar = crypto_scalar_t(hash, true);
}
