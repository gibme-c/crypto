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
// fuzz_target_rfc8032.cpp
//
// Exercises Crypto::RFC8032 (strict-spec Ed25519) sign/verify with
// adversarial byte-level inputs. RFC 8032 signatures take an arbitrary-
// length message (not a pre-hashed digest), so the fuzz body uses random
// variable-length message buffers.
//
// Paths exercised (mirrors fuzz_target_signature.cpp's structure):
//   1. check_signature(random_message, random_pk, random_sig_bytes)
//   2. generate_signature + check_signature round-trip
//   3. Tamper rejection (bit-flip in signature bytes)
//   4. Wrong-message rejection
//   5. Wrong-pk rejection
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_rfc8032(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. Adversarial check_signature --
    catch_safe(
        [&]
        {
            const size_t msg_len = r.read_u8_range(0, 128);
            const auto msg_buf = r.read_vector(msg_len);
            unsigned char pk_buf[32];
            unsigned char sig_buf[64];
            (void)r.read_bytes(pk_buf, 32);
            (void)r.read_bytes(sig_buf, 64);

            const public_key_t pk = point_t::reduce(pk_buf);
            const signature_t sig(std::vector<unsigned char>(sig_buf, sig_buf + 64));

            const bool ok = Crypto::RFC8032::check_signature(msg_buf.data(), msg_buf.size(), pk, sig);
            (void)ok;
        });

    // -- 2. Round-trip --
    catch_safe(
        [&]
        {
            unsigned char sk_buf[32];
            (void)r.read_bytes(sk_buf, 32);
            const scalar_t sk = scalar_t::from_bytes_reduced(sk_buf);
            if (sk.empty())
            {
                return;
            }
            const public_key_t pk = sk.point();

            const size_t msg_len = r.read_u8_range(0, 64);
            const auto msg = r.read_vector(msg_len);

            const signature_t sig = Crypto::RFC8032::generate_signature(msg.data(), msg.size(), sk);
            if (!Crypto::RFC8032::check_signature(msg.data(), msg.size(), pk, sig))
            {
                throw std::runtime_error("Crypto::RFC8032 round-trip: verify rejected a signature we just produced");
            }
        });

    // -- 3. Tamper rejection --
    catch_safe(
        [&]
        {
            unsigned char sk_buf[32];
            (void)r.read_bytes(sk_buf, 32);
            const scalar_t sk = scalar_t::from_bytes_reduced(sk_buf);
            if (sk.empty())
            {
                return;
            }
            const public_key_t pk = sk.point();

            const size_t msg_len = r.read_u8_range(1, 32);
            const auto msg = r.read_vector(msg_len);

            signature_t sig = Crypto::RFC8032::generate_signature(msg.data(), msg.size(), sk);
            auto sig_vec = sig.serialize();
            sig_vec[0] ^= 0x01;
            const signature_t tampered(sig_vec);

            if (Crypto::RFC8032::check_signature(msg.data(), msg.size(), pk, tampered))
            {
                throw std::runtime_error("Crypto::RFC8032 verify accepted a single-bit-flipped signature");
            }
        });

    // -- 4. Wrong-message rejection --
    catch_safe(
        [&]
        {
            unsigned char sk_buf[32];
            (void)r.read_bytes(sk_buf, 32);
            const scalar_t sk = scalar_t::from_bytes_reduced(sk_buf);
            if (sk.empty())
            {
                return;
            }
            const public_key_t pk = sk.point();

            const size_t m1_len = r.read_u8_range(1, 32);
            const auto m1 = r.read_vector(m1_len);

            const signature_t sig = Crypto::RFC8032::generate_signature(m1.data(), m1.size(), sk);

            // Construct a DIFFERENT message by bit-flipping the first byte of m1.
            auto m2 = m1;
            m2[0] ^= 0x01;

            if (Crypto::RFC8032::check_signature(m2.data(), m2.size(), pk, sig))
            {
                throw std::runtime_error("Crypto::RFC8032 verify accepted a signature under a different message");
            }
        });

    // -- 5. Wrong-pk rejection --
    catch_safe(
        [&]
        {
            unsigned char sk1_buf[32];
            unsigned char sk2_buf[32];
            (void)r.read_bytes(sk1_buf, 32);
            (void)r.read_bytes(sk2_buf, 32);
            const scalar_t sk1 = scalar_t::from_bytes_reduced(sk1_buf);
            const scalar_t sk2 = scalar_t::from_bytes_reduced(sk2_buf);
            if (sk1.empty() || sk2.empty() || sk1 == sk2)
            {
                return;
            }
            const public_key_t pk2 = sk2.point();

            const size_t msg_len = r.read_u8_range(1, 32);
            const auto msg = r.read_vector(msg_len);
            const signature_t sig = Crypto::RFC8032::generate_signature(msg.data(), msg.size(), sk1);

            if (Crypto::RFC8032::check_signature(msg.data(), msg.size(), pk2, sig))
            {
                throw std::runtime_error("Crypto::RFC8032 verify accepted a signature under the wrong public key");
            }
        });
}
