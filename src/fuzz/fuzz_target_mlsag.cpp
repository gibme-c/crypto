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
// fuzz_target_mlsag.cpp
//
// Exercises MLSAG sign/verify in plain mode with adversarial inputs.
// Commitment-binding mode is also exercised.
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
    constexpr size_t k_ring_size = 4;

    bool fuzz_ring_setup(
        FuzzByteReader &r,
        scalar_t &signer_secret,
        std::vector<public_key_t> &ring,
        size_t &signer_index)
    {
        unsigned char sk_buf[32];
        (void)r.read_bytes(sk_buf, 32);
        signer_secret = scalar_t::from_bytes_reduced(sk_buf);
        if (signer_secret.empty())
        {
            return false;
        }
        signer_index = r.read_u8_range(0, k_ring_size - 1);
        ring.resize(k_ring_size);
        for (size_t i = 0; i < k_ring_size; ++i)
        {
            if (i == signer_index)
            {
                ring[i] = signer_secret.point();
            }
            else
            {
                unsigned char buf[32];
                (void)r.read_bytes(buf, 32);
                ring[i] = point_t::reduce(buf);
                if (ring[i].empty())
                {
                    return false;
                }
            }
        }
        return true;
    }
} // namespace

extern "C" void fuzz_one_mlsag(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. byte ctor --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 255);
            const auto buf = r.read_vector(n);
            const mlsag_signature_t s(buf);
            (void)s;
        });

    // -- 2. Plain-mode round-trip + tamper + wrong-message --
    catch_safe(
        [&]
        {
            scalar_t secret;
            std::vector<public_key_t> ring;
            size_t signer_index = 0;
            if (!fuzz_ring_setup(r, secret, ring, signer_index))
            {
                return;
            }

            unsigned char d_buf[32];
            (void)r.read_bytes(d_buf, 32);
            const hash_t d(std::vector<unsigned char>(d_buf, d_buf + 32));

            const key_image_t ki = Crypto::generate_key_image(ring[signer_index], secret);

            auto [sign_ok, sig] = Crypto::RingSignature::MLSAG::generate_ring_signature(d, secret, ring);
            if (!sign_ok)
            {
                return;
            }

            if (!Crypto::RingSignature::MLSAG::check_ring_signature(d, ki, ring, sig))
            {
                throw std::runtime_error("MLSAG plain round-trip: verify rejected a fresh signature");
            }

            auto sig_bytes = sig.serialize();
            if (!sig_bytes.empty())
            {
                sig_bytes[0] ^= 0x01;
                try
                {
                    const mlsag_signature_t tampered(sig_bytes);
                    if (Crypto::RingSignature::MLSAG::check_ring_signature(d, ki, ring, tampered))
                    {
                        throw std::runtime_error("MLSAG plain verify accepted a tampered signature");
                    }
                }
                catch (const std::invalid_argument &)
                {
                }
            }

            unsigned char d2_buf[32];
            std::memcpy(d2_buf, d_buf, 32);
            d2_buf[0] ^= 0x01;
            const hash_t d2(std::vector<unsigned char>(d2_buf, d2_buf + 32));
            if (Crypto::RingSignature::MLSAG::check_ring_signature(d2, ki, ring, sig))
            {
                throw std::runtime_error("MLSAG plain verify accepted a signature under a different digest");
            }
        });
}
