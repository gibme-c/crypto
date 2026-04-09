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
        // Malformed-input contract: wrong byte length is a caller mistake.
        // Throws std::invalid_argument so downstream fuzz harnesses and
        // validators classify this as "bad input, safe to reject".
        throw std::invalid_argument("secret_key_t: input must be 32 bytes");
    }

    std::copy(input.begin(), input.end(), std::begin(bytes));

    load_hook();
}

secret_key_t::secret_key_t(const std::string &s)
{
    from_string(s);

    load_hook();
}

secret_key_t::~secret_key_t()
{
    // _prefix is a plain std::array and does not inherit a secure-erasing
    // destructor. Scrub it explicitly so the RFC 8032 signing prefix (equivalent
    // to the signing key for nonce-reuse purposes) does not outlive the
    // secret_key_t in freed memory.
    ed25519_secure_erase(_prefix.data(), _prefix.size());
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
    return _public_key;
}

std::array<unsigned char, 32> secret_key_t::rfc8032_prefix() const
{
    return _prefix;
}

void secret_key_t::load_hook()
{
    // RFC 8032 §5.1.5 key expansion: SHA-512(secret_key) splits into a lower
    // and upper half. The lower 32 bytes are pruned (clamped) and reduced to
    // form the signing scalar. The upper 32 bytes are the "signing prefix"
    // used as the secret PRF key for deterministic nonce generation by both
    // RFC 8032 Ed25519 signing and RFC 9381 ECVRF proving.
    //
    // Both halves are materialized exactly once here and cached in member
    // fields (`_scalar`, `_public_key`, `_prefix`) so that downstream callers
    // (Crypto::VRF::RFC9381::prove in particular) do not need to re-run
    // SHA-512 or the scalar-base multiplication on every operation. All three
    // members have the same lifetime as the 32-byte seed.
    //
    // This is the ONE AND ONLY caller of scalar_t::from_rfc8032_seed() in the
    // entire library. Clamping is correct for RFC 8032 private-key derivation
    // but must never be applied elsewhere; grep for `from_rfc8032_seed` to
    // enumerate every clamp site.
    //
    // The upper half of the expansion (cached in `_prefix`) is the only path
    // by which the RFC 8032 signing prefix is materialized; its sole legitimate
    // consumer is `Crypto::VRF::RFC9381::prove`.
    unsigned char hash[64];

    tinysha_sha512(bytes, sizeof(bytes), hash, 64);

    _scalar = scalar_t::from_rfc8032_seed(hash);
    _public_key = _scalar.point();
    std::copy(hash + 32, hash + 64, _prefix.begin());

    ed25519_secure_erase(hash, sizeof(hash));
}
