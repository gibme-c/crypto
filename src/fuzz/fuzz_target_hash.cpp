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
// fuzz_target_hash.cpp
//
// Exercises hash_t constructors and the fast hash primitive surface
// (SHA-256/384/512, SHA3-256, BLAKE2b) with adversarial inputs.
//
// Argon2d/i/id are INTENTIONALLY NOT fuzzed here: they are parameterized
// by iterations + memory + threads which makes a single fuzzer iteration
// expensive (seconds, not microseconds), and they are already exhaustively
// covered by the positive test battery in src/test.cpp. Fuzzing them would
// dominate wall-clock time without adding meaningful coverage.
//
// Paths exercised:
//   1. hash_t(std::vector<unsigned char>)   — byte-vector ctor. Fixed
//      32-byte size; wrong length must SAFE-throw.
//   2. hash_t::sha256                       — never throws.
//   3. hash_t::sha384                       — never throws.
//   4. hash_t::sha512                       — never throws.
//   5. hash_t::sha3                         — never throws.
//   6. hash_t::blake2b                      — never throws.
//   7. hash_t::sha3_slow with small iteration count — exercises the
//      iterated-hashing code path without blowing wall-clock.
//
// Note: hash_t has no general std::string constructor — its string-form
// ctor is JSON-only (see JSON_STRING_CONSTRUCTOR in hash_t.h). The
// deserialize-safety test suite covers the JSON path; binary
// string-to-hash has no attack surface because the only binary ingestion
// path is via std::vector<unsigned char>.
//
// These primitives should never throw on any well-formed pointer+length
// pair. A throw would mean either an internal overflow or an allocation
// failure inside the underlying hash library, both of which we want to
// know about immediately.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_hash(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. hash_t ctor from std::vector<unsigned char> --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 64);
            const std::vector<unsigned char> v = r.read_vector(n);
            hash_t h(v);
            (void)h;
        });

    // Pick a payload length once — then reuse it across every primitive
    // so each hash function sees the same input shape. Length is capped
    // because libFuzzer / smoke driver already bounds the total input
    // buffer, but a tighter per-primitive cap keeps this target's
    // iteration cost low.
    const size_t payload_len = (size > 1024) ? 1024 : size;
    const uint8_t *payload = data;

    // -- 3. hash_t::sha256 --
    catch_safe(
        [&]
        {
            const hash_t h = hash_t::sha256(payload, payload_len);
            (void)h;
        });

    // -- 4. hash_t::sha384 --
    catch_safe(
        [&]
        {
            const hash_t h = hash_t::sha384(payload, payload_len);
            (void)h;
        });

    // -- 5. hash_t::sha512 --
    catch_safe(
        [&]
        {
            const hash_t h = hash_t::sha512(payload, payload_len);
            (void)h;
        });

    // -- 6. hash_t::sha3 (SHA3-256 fast path) --
    catch_safe(
        [&]
        {
            const hash_t h = hash_t::sha3(payload, payload_len);
            (void)h;
        });

    // -- 7. hash_t::blake2b --
    catch_safe(
        [&]
        {
            const hash_t h = hash_t::blake2b(payload, payload_len);
            (void)h;
        });

    // -- 8. hash_t::sha3_slow with small iteration count --
    // The library uses sha3_slow for password-style stretching with
    // user-tunable iterations. Cap at 4 iterations to keep the fuzz
    // iteration fast.
    catch_safe(
        [&]
        {
            const hash_t h = hash_t::sha3_slow(payload, payload_len, 4);
            (void)h;
        });
}
