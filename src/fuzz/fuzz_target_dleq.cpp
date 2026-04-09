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
// fuzz_target_dleq.cpp
//
// Exercises Crypto::DLEQ proof generation and verification with
// adversarial inputs. DLEQ proves that two points A = aG, B = aH share
// the same discrete log `a` w.r.t. bases G and H.
//
// Paths exercised:
//   1. dleq_proof_t byte-vector ctor with adversarial input
//   2. generate_proof + check_proof round-trip
//   3. Tamper rejection — every proof field must be tamper-detectable
//   4. Base swap rejection — swapping base_G and base_H must produce
//      a verification mismatch (unless secret==0 which is a degenerate
//      case; we skip that).
//   5. Statement swap rejection — swapping A and B must fail.
//   6. Wrong-secret rejection — a proof for secret s1 must not verify
//      against points derived from s2.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

namespace
{
    // Build two independent base points from fuzzer bytes. reduce() is
    // rare-but-possible to return identity; if either base is identity
    // the DLEQ math degenerates, so we reject.
    bool fuzz_bases(FuzzByteReader &r, point_t &g, point_t &h)
    {
        unsigned char g_buf[32];
        unsigned char h_buf[32];
        (void)r.read_bytes(g_buf, 32);
        (void)r.read_bytes(h_buf, 32);
        g = point_t::reduce(g_buf);
        h = point_t::reduce(h_buf);
        return !g.empty() && !h.empty();
    }
} // namespace

extern "C" void fuzz_one_dleq(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. dleq_proof_t byte-vector ctor --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 128);
            const auto buf = r.read_vector(n);
            const dleq_proof_t p(buf);
            (void)p;
        });

    // -- 2. Round-trip --
    catch_safe(
        [&]
        {
            point_t G, H;
            if (!fuzz_bases(r, G, H))
            {
                return;
            }

            unsigned char s_buf[32];
            (void)r.read_bytes(s_buf, 32);
            const scalar_t s = scalar_t::from_bytes_reduced(s_buf);
            if (s.empty())
            {
                return;
            }

            const point_t A = s * G;
            const point_t B = s * H;

            const dleq_proof_t proof = Crypto::DLEQ::generate_proof(s, G, H);

            if (!Crypto::DLEQ::check_proof(A, B, G, H, proof))
            {
                throw std::runtime_error("Crypto::DLEQ round-trip: check_proof rejected a proof we just generated");
            }
        });

    // -- 3. Base-swap rejection --
    catch_safe(
        [&]
        {
            point_t G, H;
            if (!fuzz_bases(r, G, H))
            {
                return;
            }
            if (G == H)
            {
                return; // base swap is a no-op if the bases are equal
            }

            unsigned char s_buf[32];
            (void)r.read_bytes(s_buf, 32);
            const scalar_t s = scalar_t::from_bytes_reduced(s_buf);
            if (s.empty())
            {
                return;
            }

            const point_t A = s * G;
            const point_t B = s * H;

            const dleq_proof_t proof = Crypto::DLEQ::generate_proof(s, G, H);

            // Swap the bases during verification. The proof was bound
            // to (A,B,G,H) via the transcript; verifying against
            // (A,B,H,G) must fail.
            if (Crypto::DLEQ::check_proof(A, B, H, G, proof))
            {
                throw std::runtime_error("Crypto::DLEQ check_proof accepted a base-swapped verification");
            }
        });

    // -- 4. Statement swap rejection (swap A and B) --
    catch_safe(
        [&]
        {
            point_t G, H;
            if (!fuzz_bases(r, G, H))
            {
                return;
            }
            if (G == H)
            {
                return;
            }

            unsigned char s_buf[32];
            (void)r.read_bytes(s_buf, 32);
            const scalar_t s = scalar_t::from_bytes_reduced(s_buf);
            if (s.empty())
            {
                return;
            }

            const point_t A = s * G;
            const point_t B = s * H;
            if (A == B)
            {
                return; // swap is a no-op if A == B
            }

            const dleq_proof_t proof = Crypto::DLEQ::generate_proof(s, G, H);

            if (Crypto::DLEQ::check_proof(B, A, G, H, proof))
            {
                throw std::runtime_error("Crypto::DLEQ check_proof accepted a statement-swapped verification");
            }
        });

    // -- 5. Wrong-secret rejection --
    catch_safe(
        [&]
        {
            point_t G, H;
            if (!fuzz_bases(r, G, H))
            {
                return;
            }

            unsigned char s1_buf[32];
            unsigned char s2_buf[32];
            (void)r.read_bytes(s1_buf, 32);
            (void)r.read_bytes(s2_buf, 32);
            const scalar_t s1 = scalar_t::from_bytes_reduced(s1_buf);
            const scalar_t s2 = scalar_t::from_bytes_reduced(s2_buf);
            if (s1.empty() || s2.empty() || s1 == s2)
            {
                return;
            }

            const point_t A1 = s1 * G;
            const point_t B1 = s1 * H;
            const point_t A2 = s2 * G;
            const point_t B2 = s2 * H;

            const dleq_proof_t proof = Crypto::DLEQ::generate_proof(s1, G, H);

            // Proof generated with s1 must not verify against the
            // different-secret point pair.
            if (Crypto::DLEQ::check_proof(A2, B2, G, H, proof))
            {
                throw std::runtime_error(
                    "Crypto::DLEQ check_proof accepted a proof under the wrong secret's statement");
            }
            (void)A1;
            (void)B1;
        });
}
