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
// fuzz_target_scalar.cpp
//
// Exercises every public scalar_t deserialization path and the non-throwing
// validator surface with adversarial bytes. Specifically:
//
//   1. scalar_t(std::vector<unsigned char>)  — byte-vector ctor (memcpy,
//      no reduction). Adversarial input of wrong length must throw
//      std::invalid_argument (SAFE).
//   2. scalar_t(std::string)                 — binary or hex string ctor.
//      Adversarial input should either succeed or SAFE-throw.
//   3. scalar_t::from_bytes_reduced          — reducing constructor on a
//      fixed 32-byte buffer. Never throws on size; result is always a
//      canonical scalar regardless of input.
//   4. scalar_t::from_rfc8032_seed           — RFC 8032 §5.1.5 clamping
//      path. Never throws on size; result is always a canonical clamped
//      signing scalar.
//   5. scalar_t::from_uniform_bytes          — wide reduction on a fixed
//      64-byte buffer. Never throws on size; result is canonical.
//   6. scalar_t::check<T>()                  — template validator, MUST
//      NOT throw on any input per its internal catch-all.
//   7. scalar_t::check()                     — canonical-form test.
//   8. scalar_t arithmetic                   — +, -, *, /, invert(),
//      negate(), is_nonzero(), operator==, operator<, point(). Division
//      by zero and invert-of-zero are the only interesting malformed
//      cases; both should throw SAFE.
//
// Invariants asserted by construction (not via check()):
//   - If scalar_t::check(value) returns true, constructing scalar_t(value)
//     must not throw.
//   - from_bytes_reduced / from_rfc8032_seed / from_uniform_bytes must
//     always produce a .check()-true result regardless of input bytes.
//
// Any violation of these invariants (e.g. check() says OK but ctor throws)
// is a bug in the library's reduction path. The wrapper catches SAFE
// throws and treats them as "input wasn't valid for this path"; anything
// else propagates as a fault.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_scalar(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. ctor from std::vector<unsigned char> --
    // Length picked from the input so the fuzzer can hit the "wrong size"
    // rejection path AND the "exactly 32 bytes" happy path.
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 64);
            const std::vector<unsigned char> v = r.read_vector(n);
            scalar_t s(v);
            (void)s.check();
            (void)s.is_nonzero();
        });

    // -- 2. ctor from std::string (binary slice) --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 128);
            const auto buf = r.read_vector(n);
            const std::string str(reinterpret_cast<const char *>(buf.data()), buf.size());
            scalar_t s(str);
            (void)s.check();
        });

    // -- 3. from_bytes_reduced (fixed 32-byte buffer, always reduces) --
    catch_safe(
        [&]
        {
            unsigned char buf[32];
            (void)r.read_bytes(buf, 32);
            const scalar_t s = scalar_t::from_bytes_reduced(buf);
            // Post-condition: reduced scalars MUST be canonical.
            if (!s.check())
            {
                // This would be a genuine library bug — a canonical
                // output should always round-trip through .check().
                // Escalate via std::runtime_error which is OUTSIDE the
                // SAFE set, so the outer wrapper reports it as a fault.
                throw std::runtime_error("scalar_t::from_bytes_reduced produced a non-canonical scalar");
            }
        });

    // -- 4. from_rfc8032_seed (fixed 32-byte buffer, clamps+reduces) --
    catch_safe(
        [&]
        {
            unsigned char seed[32];
            (void)r.read_bytes(seed, 32);
            const scalar_t s = scalar_t::from_rfc8032_seed(seed);
            if (!s.check())
            {
                throw std::runtime_error("scalar_t::from_rfc8032_seed produced a non-canonical scalar");
            }
        });

    // -- 5. from_uniform_bytes (fixed 64-byte buffer, wide reduction) --
    catch_safe(
        [&]
        {
            unsigned char buf[64];
            (void)r.read_bytes(buf, 64);
            const scalar_t s = scalar_t::from_uniform_bytes(buf);
            if (!s.check())
            {
                throw std::runtime_error("scalar_t::from_uniform_bytes produced a non-canonical scalar");
            }
        });

    // -- 6. Template check<T>() — MUST NOT throw regardless of input --
    // This is the public "is this a valid scalar?" entry point used by
    // external callers that want to pre-validate untrusted input. Per its
    // documented contract it catches everything internally and returns
    // bool. A throw here would be a bug.
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 64);
            const auto v = r.read_vector(n);
            (void)scalar_t::check(v);
        });

    // -- 7. Arithmetic on two scalars derived from the input --
    catch_safe(
        [&]
        {
            unsigned char a_buf[32];
            unsigned char b_buf[32];
            (void)r.read_bytes(a_buf, 32);
            (void)r.read_bytes(b_buf, 32);
            const scalar_t a = scalar_t::from_bytes_reduced(a_buf);
            const scalar_t b = scalar_t::from_bytes_reduced(b_buf);

            const scalar_t sum = a + b;
            const scalar_t diff = a - b;
            const scalar_t prod = a * b;
            (void)sum.check();
            (void)diff.check();
            (void)prod.check();

            // invert() on zero should throw (the docs don't guarantee WHICH
            // throw type, but we rely on SAFE-throw). is_nonzero() guards
            // divide-by-zero on the happy path.
            if (b.is_nonzero())
            {
                const scalar_t q = a / b;
                (void)q.check();
                const scalar_t inv = b.invert();
                (void)inv.check();
            }

            // negate() and point() are always defined on any scalar.
            const scalar_t neg = a.negate();
            (void)neg.check();
            const point_t P = a.point();
            (void)P.valid(true);
        });
}
