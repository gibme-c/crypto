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
 * @file secret_key_t.cpp
 * @brief RFC-8032 Ed25519 secret key: SHA-512 expansion with clamping to derive the signing scalar.
 */

#include <ed25519/include/ed25519_secure_erase.h>
#include <helpers/constant_time.h>
#include <tinysha.h>
#include <types/secret_key_t.h>

secret_key_t::secret_key_t(std::initializer_list<unsigned char> input)
{
    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

secret_key_t::secret_key_t(const std::vector<unsigned char> &input)
{
    if (input.size() != sizeof(bytes))
    {
        throw std::runtime_error("could not load secret key");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

secret_key_t::secret_key_t(const std::string &s)
{
    from_string(s);

    load_hook();
}

secret_key_t::operator scalar_t() const
{
    return scalar();
}

bool secret_key_t::operator==(const secret_key_t &other) const
{
    return constant_time_equals(bytes, other.bytes, sizeof(bytes));
}

bool secret_key_t::operator!=(const secret_key_t &other) const
{
    return !(*this == other);
}

scalar_t secret_key_t::scalar() const
{
    return _scalar;
}

point_t secret_key_t::point() const
{
    return _scalar.point();
}

void secret_key_t::load_hook()
{
    // RFC-8032 key expansion: SHA-512(secret_key), then take the lower 32 bytes
    // and apply clamping + reduction to produce the signing scalar.
    // The upper 32 bytes (discarded here) are used as nonce prefix during signing.
    unsigned char hash[64];

    tinysha_sha512(bytes, sizeof(bytes), hash, 64);

    std::vector<unsigned char> lower(hash, hash + 32);

    _scalar = scalar_t(lower, true);

    ed25519_secure_erase(hash, sizeof(hash));
    ed25519_secure_erase(lower.data(), lower.size());
}
