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
// fuzz_target_point.cpp
//
// Exercises point_t deserialization and the non-throwing validator surface
// with adversarial bytes. Point decompression is arguably the single most
// security-critical parser in the library: Ed25519 point encoding is a
// 32-byte compressed form that can fail in multiple ways (not on the curve,
// non-canonical field element, small-subgroup contamination), and every
// verifier downstream assumes that a successfully-constructed point_t is
// on the curve.
//
// Paths exercised:
//   1. point_t(std::vector<unsigned char>)  — byte-vector ctor. Must SAFE-throw
//      on wrong length; must SAFE-throw on non-curve bytes.
//   2. point_t(std::string)                 — string ctor. Same policy.
//   3. point_t::check<T>()                  — template validator, MUST NOT
//      throw for any input per its internal catch-all.
//   4. point_t::reduce(const unsigned char[32]) — hash-to-curve (unlike the
//      constructor, this always succeeds regardless of input bytes). The
//      result MUST always be a valid curve point.
//   5. point_t::from_uint256                — treats a uint256_t as 32
//      point bytes. Same failure modes as the vector ctor.
//   6. point_t::check()                     — curve-membership test.
//   7. point_t::check_subgroup()            — prime-order subgroup test.
//      CRITICAL for ring-signature + range-proof verifiers. Must not
//      throw regardless of which torsion class the point is in.
//   8. point_t::mul8()                      — cofactor clearing. Must
//      always produce a valid subgroup element.
//   9. Arithmetic (+, -, negate, scalar*point).
//  10. valid() / empty().
//
// Invariants asserted by construction:
//   - If a point_t was constructed successfully via the vector/string ctor,
//     .check() must return true (curve membership).
//   - point_t::reduce(bytes) MUST always return a valid curve point, and
//     .check_subgroup() MUST return true on the reduced result.
//   - mul8() of any valid point must itself be a valid subgroup element.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_point(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. ctor from std::vector<unsigned char> --
    // Variable length. The happy path is exactly 32 bytes; shorter/longer
    // must SAFE-throw. A successful construction must produce a point
    // that passes .check() (curve membership).
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 64);
            const std::vector<unsigned char> v = r.read_vector(n);
            point_t P(v);
            // If we get here, n was 32 AND the bytes happened to decode
            // to a valid curve point. That's exactly the happy path the
            // constructor's ~1-in-2 probability gives us on random input.
            if (!P.check())
            {
                throw std::runtime_error("point_t(vector) constructed successfully but .check() returned false");
            }
            // Subgroup check is allowed to return false — non-subgroup
            // curve points are legitimate decodings of non-canonical
            // wire-format bytes. But it must not THROW.
            (void)P.check_subgroup();
            (void)P.valid(true);
            (void)P.empty();
        });

    // -- 2. ctor from std::string (binary slice) --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 128);
            const auto buf = r.read_vector(n);
            const std::string str(reinterpret_cast<const char *>(buf.data()), buf.size());
            point_t P(str);
            if (!P.check())
            {
                throw std::runtime_error("point_t(string) constructed successfully but .check() returned false");
            }
        });

    // -- 3. Template check<T>() — MUST NOT throw regardless of input --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 64);
            const auto v = r.read_vector(n);
            (void)point_t::check(v);
        });

    // -- 4. hash-to-curve reduce() — always produces a valid curve point --
    //
    // Contract (per include/types/point_t.h:187-192): reduce(any 32 bytes)
    // MUST return a valid curve point (.check() true). The docstring does
    // NOT promise subgroup membership in the strict sense that
    // check_subgroup() enforces — check_subgroup() explicitly rejects the
    // identity point, but reduce() CAN produce identity for certain
    // Elligator preimages that map to 8-torsion (mul8 zeros them out).
    //
    // Identity is a rare-but-legal reduce() output; downstream callers
    // that need nonzero points are responsible for checking .empty()
    // themselves. The harness assertion below accepts identity as
    // in-contract.
    catch_safe(
        [&]
        {
            unsigned char buf[32];
            (void)r.read_bytes(buf, 32);
            const point_t P = point_t::reduce(buf);
            if (!P.check())
            {
                throw std::runtime_error("point_t::reduce produced a point that fails .check()");
            }
            // Subgroup assertion: accept check_subgroup() true OR identity.
            // See the block comment above for the rationale.
            if (!P.check_subgroup() && !P.empty())
            {
                throw std::runtime_error("point_t::reduce produced a point outside the prime-order subgroup");
            }
        });

    // -- 5. mul8() and negate() on a reduced (always-valid) point --
    //
    // Same subgroup-or-identity carve-out as above. A reduced point that
    // happens to land on identity stays identity under mul8, and mul8 of
    // any other 8-torsion-contaminated point also produces identity when
    // the prime-order component is exactly zero.
    catch_safe(
        [&]
        {
            unsigned char buf[32];
            (void)r.read_bytes(buf, 32);
            const point_t P = point_t::reduce(buf);

            const point_t P8 = P.mul8();
            if (!P8.check())
            {
                throw std::runtime_error("point_t::mul8 produced a point that fails .check()");
            }
            if (!P8.check_subgroup() && !P8.empty())
            {
                throw std::runtime_error("point_t::mul8 produced a point outside the prime-order subgroup");
            }

            const point_t neg = P.negate();
            if (!neg.check())
            {
                throw std::runtime_error("point_t::negate produced a point that fails .check()");
            }
        });

    // -- 6. Arithmetic (+, -) on two reduced points --
    catch_safe(
        [&]
        {
            unsigned char a_buf[32];
            unsigned char b_buf[32];
            (void)r.read_bytes(a_buf, 32);
            (void)r.read_bytes(b_buf, 32);
            const point_t A = point_t::reduce(a_buf);
            const point_t B = point_t::reduce(b_buf);

            const point_t sum = A + B;
            const point_t diff = A - B;
            if (!sum.check() || !diff.check())
            {
                throw std::runtime_error("point_t arithmetic produced a non-curve point");
            }
        });

    // -- 7. Scalar * point (derive a random pubkey from a reduced scalar) --
    catch_safe(
        [&]
        {
            unsigned char s_buf[32];
            unsigned char p_buf[32];
            (void)r.read_bytes(s_buf, 32);
            (void)r.read_bytes(p_buf, 32);
            const scalar_t s = scalar_t::from_bytes_reduced(s_buf);
            const point_t P = point_t::reduce(p_buf);
            const point_t R = s * P;
            if (!R.check())
            {
                throw std::runtime_error("scalar * point produced a non-curve point");
            }
        });
}
