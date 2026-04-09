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

// ---------------------------------------------------------------------------
// fuzz_target_addresses.cpp
//
// Exercises Crypto::Address::Base58 and Crypto::Address::CNBase58 encode/
// decode paths. Address encoding wraps Base58 / CNBase58 with a namespace
// prefix (uint64_t) + one or two public keys + a checksum. Decoders return
// a tuple {ok, prefix, pubkey1, pubkey2} where ok=false on any failure
// and the decoder MUST NOT throw on arbitrary std::string input.
//
// Paths exercised (per namespace — Base58 and CNBase58):
//   1. Address::decode(random string)          — failure path
//   2. Address::encode(prefix, pubkey) round-trip (single-key)
//   3. Address::encode(prefix, spend, view) round-trip (dual-key)
//
// The round-trip path uses point_t::reduce to build always-valid random
// public keys from fuzzer bytes, rather than trying to construct them from
// random byte strings (which would SAFE-throw most of the time and burn
// coverage).
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <string>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

namespace
{
    // Build a valid public_key_t from fuzzer bytes via the hash-to-curve
    // reduce() path. That path may produce the identity point for certain
    // inputs (documented in fuzz_target_point.cpp); address encode may or
    // may not accept identity. The fuzz body catches SAFE throws if the
    // encode path rejects it.
    public_key_t fuzz_public_key(FuzzByteReader &r)
    {
        unsigned char buf[32];
        (void)r.read_bytes(buf, 32);
        const point_t P = point_t::reduce(buf);
        return public_key_t(P.serialize());
    }
} // namespace

extern "C" void fuzz_one_addresses(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. Address::Base58::decode(random string) — failure path --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 200);
            const auto buf = r.read_vector(n);
            const std::string input(reinterpret_cast<const char *>(buf.data()), buf.size());

            auto [ok, prefix, pk1, pk2] = Crypto::Address::Base58::decode(input);
            (void)ok;
            (void)prefix;
            (void)pk1;
            (void)pk2;
        });

    // -- 2. Address::Base58 single-key round-trip --
    catch_safe(
        [&]
        {
            const uint64_t prefix = r.read_u32_le();
            const public_key_t pk = fuzz_public_key(r);

            const std::string addr = Crypto::Address::Base58::encode(prefix, pk);
            auto [ok, decoded_prefix, decoded_pk1, decoded_pk2] = Crypto::Address::Base58::decode(addr);

            if (!ok)
            {
                throw std::runtime_error("Address::Base58 single-key round-trip: decode returned false");
            }
            if (decoded_prefix != prefix)
            {
                throw std::runtime_error("Address::Base58 single-key round-trip: prefix mismatch");
            }
            if (!(decoded_pk1 == pk))
            {
                throw std::runtime_error("Address::Base58 single-key round-trip: pk mismatch");
            }
        });

    // -- 3. Address::Base58 dual-key round-trip --
    catch_safe(
        [&]
        {
            const uint64_t prefix = r.read_u32_le();
            const public_key_t spend = fuzz_public_key(r);
            const public_key_t view = fuzz_public_key(r);

            const std::string addr = Crypto::Address::Base58::encode(prefix, spend, view);
            auto [ok, decoded_prefix, decoded_spend, decoded_view] = Crypto::Address::Base58::decode(addr);

            if (!ok)
            {
                throw std::runtime_error("Address::Base58 dual-key round-trip: decode returned false");
            }
            if (decoded_prefix != prefix)
            {
                throw std::runtime_error("Address::Base58 dual-key round-trip: prefix mismatch");
            }
            if (!(decoded_spend == spend))
            {
                throw std::runtime_error("Address::Base58 dual-key round-trip: spend key mismatch");
            }
            if (!(decoded_view == view))
            {
                throw std::runtime_error("Address::Base58 dual-key round-trip: view key mismatch");
            }
        });

    // -- 4. Address::CNBase58::decode(random string) --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 200);
            const auto buf = r.read_vector(n);
            const std::string input(reinterpret_cast<const char *>(buf.data()), buf.size());

            auto [ok, prefix, pk1, pk2] = Crypto::Address::CNBase58::decode(input);
            (void)ok;
            (void)prefix;
            (void)pk1;
            (void)pk2;
        });

    // -- 5. Address::CNBase58 single-key round-trip --
    catch_safe(
        [&]
        {
            const uint64_t prefix = r.read_u32_le();
            const public_key_t pk = fuzz_public_key(r);

            const std::string addr = Crypto::Address::CNBase58::encode(prefix, pk);
            auto [ok, decoded_prefix, decoded_pk1, decoded_pk2] = Crypto::Address::CNBase58::decode(addr);

            if (!ok)
            {
                throw std::runtime_error("Address::CNBase58 single-key round-trip: decode returned false");
            }
            if (decoded_prefix != prefix)
            {
                throw std::runtime_error("Address::CNBase58 single-key round-trip: prefix mismatch");
            }
            if (!(decoded_pk1 == pk))
            {
                throw std::runtime_error("Address::CNBase58 single-key round-trip: pk mismatch");
            }
        });

    // -- 6. Address::CNBase58 dual-key round-trip --
    catch_safe(
        [&]
        {
            const uint64_t prefix = r.read_u32_le();
            const public_key_t spend = fuzz_public_key(r);
            const public_key_t view = fuzz_public_key(r);

            const std::string addr = Crypto::Address::CNBase58::encode(prefix, spend, view);
            auto [ok, decoded_prefix, decoded_spend, decoded_view] = Crypto::Address::CNBase58::decode(addr);

            if (!ok)
            {
                throw std::runtime_error("Address::CNBase58 dual-key round-trip: decode returned false");
            }
            if (decoded_prefix != prefix)
            {
                throw std::runtime_error("Address::CNBase58 dual-key round-trip: prefix mismatch");
            }
            if (!(decoded_spend == spend))
            {
                throw std::runtime_error("Address::CNBase58 dual-key round-trip: spend key mismatch");
            }
            if (!(decoded_view == view))
            {
                throw std::runtime_error("Address::CNBase58 dual-key round-trip: view key mismatch");
            }
        });
}
