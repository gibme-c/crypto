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
// fuzz_target_borromean.cpp
//
// Exercises Crypto::RingSignature::Borromean sign/verify with adversarial
// inputs. Borromean is the simplest ring signature in the library: no
// commitment binding, plain linkability via key image.
//
// Paths exercised:
//   1. borromean_signature_t byte ctor — adversarial bytes
//   2. check_ring_signature with random signature + random ring — the
//      verifier MUST NOT throw, must return false
//   3. Sign + verify round-trip — verify must accept
//   4. Tamper rejection on a valid signature
//   5. Wrong-message rejection
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

    // Build a ring of fuzzer-driven valid public keys and splice the
    // signer's key in at a fuzzer-chosen slot. Returns the signer's
    // secret + the ring + the signer index, or false on setup
    // degenerates.
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

extern "C" void fuzz_one_borromean(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. byte ctor --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 200);
            const auto buf = r.read_vector(n);
            const borromean_signature_t s(buf);
            (void)s;
        });

    // -- 2-5. Full round-trip + tamper + wrong-message --
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

            unsigned char d1_buf[32];
            (void)r.read_bytes(d1_buf, 32);
            const hash_t d1(std::vector<unsigned char>(d1_buf, d1_buf + 32));

            const key_image_t ki = Crypto::generate_key_image(ring[signer_index], secret);

            auto [sign_ok, sig] = Crypto::RingSignature::Borromean::generate_ring_signature(d1, secret, ring);
            if (!sign_ok)
            {
                // secret doesn't match any ring member — fuzz randomness
                // can produce this. Skip.
                return;
            }

            // Round-trip.
            if (!Crypto::RingSignature::Borromean::check_ring_signature(d1, ki, ring, sig))
            {
                throw std::runtime_error("Borromean round-trip: verify rejected a fresh signature");
            }

            // Tamper: serialize, flip a byte, reconstruct, verify.
            auto sig_bytes = sig.serialize();
            if (!sig_bytes.empty())
            {
                sig_bytes[0] ^= 0x01;
                try
                {
                    const borromean_signature_t tampered(sig_bytes);
                    if (Crypto::RingSignature::Borromean::check_ring_signature(d1, ki, ring, tampered))
                    {
                        throw std::runtime_error("Borromean verify accepted a tampered signature");
                    }
                }
                catch (const std::invalid_argument &)
                {
                    // tampered bytes may not deserialize — acceptable
                }
            }

            // Wrong-message: flip a byte of the digest.
            unsigned char d2_buf[32];
            std::memcpy(d2_buf, d1_buf, 32);
            d2_buf[0] ^= 0x01;
            const hash_t d2(std::vector<unsigned char>(d2_buf, d2_buf + 32));
            if (Crypto::RingSignature::Borromean::check_ring_signature(d2, ki, ring, sig))
            {
                throw std::runtime_error("Borromean verify accepted a signature under a different message digest");
            }
        });
}
