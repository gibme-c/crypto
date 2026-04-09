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
// fuzz_target_signature.cpp
//
// Exercises Crypto::Signature (the library's custom Ed25519 Schnorr
// variant) sign/verify with adversarial byte-level inputs.
//
// Paths exercised:
//   1. check_signature(random_digest, random_pk, random_sig_bytes)
//      — adversarial input path. Random bytes almost never form a valid
//      signature, so the overwhelming majority of iterations hit the
//      false-return branch. Must NEVER throw.
//   2. generate_signature + check_signature round-trip — must verify.
//   3. Tamper rejection — flipping a byte in the signature must make
//      check_signature return false (NOT throw). This is the single
//      most important property of any signature verifier.
//   4. Wrong-message rejection — verifying a valid signature against a
//      DIFFERENT digest must return false.
//   5. Wrong-pk rejection — verifying against a different public key
//      must return false.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_signature(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. check_signature with adversarial signature bytes --
    catch_safe(
        [&]
        {
            unsigned char d_buf[32];
            unsigned char pk_buf[32];
            unsigned char sig_buf[64];
            (void)r.read_bytes(d_buf, 32);
            (void)r.read_bytes(pk_buf, 32);
            (void)r.read_bytes(sig_buf, 64);

            const hash_t digest(std::vector<unsigned char>(d_buf, d_buf + 32));
            const public_key_t pk = point_t::reduce(pk_buf);
            // signature_t vector ctor — may SAFE-throw if 64 bytes don't
            // parse as a valid signature_t, caught by the outer wrapper.
            const signature_t sig(std::vector<unsigned char>(sig_buf, sig_buf + 64));

            const bool ok = Crypto::Signature::check_signature(digest, pk, sig);
            (void)ok;
        });

    // -- 2. Round-trip sign + verify --
    catch_safe(
        [&]
        {
            unsigned char sk_buf[32];
            unsigned char d_buf[32];
            (void)r.read_bytes(sk_buf, 32);
            (void)r.read_bytes(d_buf, 32);

            const scalar_t sk = scalar_t::from_bytes_reduced(sk_buf);
            if (sk.empty())
            {
                return; // skip identity secret
            }
            const public_key_t pk = sk.point();
            const hash_t digest(std::vector<unsigned char>(d_buf, d_buf + 32));

            const signature_t sig = Crypto::Signature::generate_signature(digest, sk);
            if (!Crypto::Signature::check_signature(digest, pk, sig))
            {
                throw std::runtime_error("Crypto::Signature round-trip: verify rejected a signature we just produced");
            }
        });

    // -- 3. Tamper rejection --
    catch_safe(
        [&]
        {
            unsigned char sk_buf[32];
            unsigned char d_buf[32];
            (void)r.read_bytes(sk_buf, 32);
            (void)r.read_bytes(d_buf, 32);

            const scalar_t sk = scalar_t::from_bytes_reduced(sk_buf);
            if (sk.empty())
            {
                return;
            }
            const public_key_t pk = sk.point();
            const hash_t digest(std::vector<unsigned char>(d_buf, d_buf + 32));

            signature_t sig = Crypto::Signature::generate_signature(digest, sk);
            auto sig_vec = sig.serialize();
            // Flip the first byte of the signature.
            sig_vec[0] ^= 0x01;
            const signature_t tampered(sig_vec);

            if (Crypto::Signature::check_signature(digest, pk, tampered))
            {
                throw std::runtime_error("Crypto::Signature verify accepted a single-bit-flipped signature");
            }
        });

    // -- 4. Wrong-message rejection --
    catch_safe(
        [&]
        {
            unsigned char sk_buf[32];
            unsigned char d1_buf[32];
            unsigned char d2_buf[32];
            (void)r.read_bytes(sk_buf, 32);
            (void)r.read_bytes(d1_buf, 32);
            (void)r.read_bytes(d2_buf, 32);
            // Ensure d1 != d2.
            if (std::memcmp(d1_buf, d2_buf, 32) == 0)
            {
                d2_buf[0] ^= 0xFF;
            }

            const scalar_t sk = scalar_t::from_bytes_reduced(sk_buf);
            if (sk.empty())
            {
                return;
            }
            const public_key_t pk = sk.point();
            const hash_t d1(std::vector<unsigned char>(d1_buf, d1_buf + 32));
            const hash_t d2(std::vector<unsigned char>(d2_buf, d2_buf + 32));

            const signature_t sig = Crypto::Signature::generate_signature(d1, sk);
            if (Crypto::Signature::check_signature(d2, pk, sig))
            {
                throw std::runtime_error(
                    "Crypto::Signature verify accepted a signature under a different message digest");
            }
        });

    // -- 5. Wrong-pk rejection --
    catch_safe(
        [&]
        {
            unsigned char sk1_buf[32];
            unsigned char sk2_buf[32];
            unsigned char d_buf[32];
            (void)r.read_bytes(sk1_buf, 32);
            (void)r.read_bytes(sk2_buf, 32);
            (void)r.read_bytes(d_buf, 32);

            const scalar_t sk1 = scalar_t::from_bytes_reduced(sk1_buf);
            const scalar_t sk2 = scalar_t::from_bytes_reduced(sk2_buf);
            if (sk1.empty() || sk2.empty())
            {
                return;
            }
            if (sk1 == sk2)
            {
                return;
            }
            const public_key_t pk1 = sk1.point();
            const public_key_t pk2 = sk2.point();
            const hash_t digest(std::vector<unsigned char>(d_buf, d_buf + 32));

            const signature_t sig = Crypto::Signature::generate_signature(digest, sk1);
            if (Crypto::Signature::check_signature(digest, pk2, sig))
            {
                throw std::runtime_error("Crypto::Signature verify accepted a signature under the wrong public key");
            }
        });
}
