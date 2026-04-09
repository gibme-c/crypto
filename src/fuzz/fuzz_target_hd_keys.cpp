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
// fuzz_target_hd_keys.cpp
//
// Exercises the SLIP-10 / BIP-32 hierarchical deterministic key derivation
// surface. This is the ONLY module where we fuzz a string-based parser at
// the primitive level — specifically, the BIP-32 path parser that converts
// strings like "m/44'/0'/0'/0'/0'" into child-derivation indices.
//
// Paths exercised:
//   1. calculate_hmac_sha512(key, key_len, msg, msg_len)
//      — the HMAC primitive that underpins all HD derivation. Must never
//      throw on any (non-null) pointer pair.
//   2. generate_hd_child_key(parent_key, chain_code, path)
//      — the full SLIP-10 derivation. Path parser is the attack surface:
//      malformed path strings (non-numeric, trailing junk, bare apostrophe,
//      unhardened segments, out-of-range indices) must SAFE-throw. Valid
//      paths must produce a result regardless of parent key content.
//   3. hd_key_t(key_hash, chain_hash) + generate_child_key(int args)
//      — integer-index child derivation. Path indices are picked from the
//      fuzzer bytes. Tests the non-string derivation entry point.
//   4. hd_key_t::generate_child_key(string_path)
//      — string-path derivation from a full hd_key_t. Same parser as (2)
//      but exercised through the higher-level wrapper.
//
// Note: the SLIP-10 implementation REQUIRES fully-hardened paths on
// Ed25519. An unhardened segment in the path string is expected to
// SAFE-throw; that's the documented contract the parser enforces.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

namespace
{
    // Build a plausible BIP-32 path string from a byte slice. The grammar
    // is intentionally lax: we pick 1-6 segments, each a small integer
    // optionally followed by an apostrophe (hardened marker). This lets
    // the fuzzer hit both valid paths AND the many invalid-path SAFE-throw
    // rejection cases.
    std::string make_fuzz_path(FuzzByteReader &r)
    {
        std::string path = "m";
        const size_t segments = static_cast<size_t>(r.read_u8_range(0, 6));
        for (size_t i = 0; i < segments; ++i)
        {
            path.push_back('/');
            // Index value — fuzz byte determines the magnitude. Bit 7
            // selects hardened vs unhardened (unhardened is invalid for
            // SLIP-10, so that forces the rejection path).
            const uint8_t b = r.read_u8();
            const uint32_t idx = static_cast<uint32_t>(b & 0x7F) * 1u;
            path.append(std::to_string(idx));
            if ((b & 0x80) != 0)
            {
                path.push_back('\'');
            }
        }
        // Occasionally append garbage to exercise the tail-rejection
        // path in the parser.
        if ((r.read_u8() & 0x0F) == 0)
        {
            path.append("junk");
        }
        return path;
    }
} // namespace

extern "C" void fuzz_one_hd_keys(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. calculate_hmac_sha512 with fuzzer-sized key + message --
    catch_safe(
        [&]
        {
            const size_t key_len = r.read_u8_range(0, 128);
            const size_t msg_len = r.read_u8_range(0, 128);
            const auto key = r.read_vector(key_len);
            const auto msg = r.read_vector(msg_len);
            const auto hmac = calculate_hmac_sha512(key.data(), key.size(), msg.data(), msg.size());
            (void)hmac;
        });

    // -- 2. generate_hd_child_key with fuzzer-chosen parent + path --
    catch_safe(
        [&]
        {
            unsigned char pk_buf[32];
            unsigned char cc_buf[32];
            (void)r.read_bytes(pk_buf, 32);
            (void)r.read_bytes(cc_buf, 32);
            const std::vector<unsigned char> pk_vec(pk_buf, pk_buf + 32);
            const std::vector<unsigned char> cc_vec(cc_buf, cc_buf + 32);
            const hash_t parent_key(pk_vec);
            const hash_t chain_code(cc_vec);

            const std::string path = make_fuzz_path(r);
            const auto [child_key, child_cc] = generate_hd_child_key(parent_key, chain_code, path);
            (void)child_key;
            (void)child_cc;
        });

    // -- 3. hd_key_t(hash, hash) + integer-index child derivation --
    catch_safe(
        [&]
        {
            unsigned char pk_buf[32];
            unsigned char cc_buf[32];
            (void)r.read_bytes(pk_buf, 32);
            (void)r.read_bytes(cc_buf, 32);
            const hash_t parent_key(std::vector<unsigned char>(pk_buf, pk_buf + 32));
            const hash_t chain_code(std::vector<unsigned char>(cc_buf, cc_buf + 32));

            hd_key_t root(parent_key, chain_code);

            // Integer indices — capped to keep stack work bounded.
            const size_t a = r.read_u8_range(0, 255);
            const size_t b = r.read_u8_range(0, 255);
            const size_t c = r.read_u8_range(0, 255);
            const size_t d = r.read_u8_range(0, 255);
            const size_t e = r.read_u8_range(0, 255);

            const hd_key_t derived = root.generate_child_key(a, b, c, d, e);
            (void)derived.public_key();
            (void)derived.secret_key();
            (void)derived.chain_code();
            (void)derived.key();
        });

    // -- 4. hd_key_t::generate_child_key(std::string) --
    catch_safe(
        [&]
        {
            unsigned char pk_buf[32];
            unsigned char cc_buf[32];
            (void)r.read_bytes(pk_buf, 32);
            (void)r.read_bytes(cc_buf, 32);
            const hash_t parent_key(std::vector<unsigned char>(pk_buf, pk_buf + 32));
            const hash_t chain_code(std::vector<unsigned char>(cc_buf, cc_buf + 32));

            const hd_key_t root(parent_key, chain_code);
            const std::string path = make_fuzz_path(r);
            const hd_key_t derived = root.generate_child_key(path);
            (void)derived.public_key();
            (void)derived.secret_key();
        });
}
