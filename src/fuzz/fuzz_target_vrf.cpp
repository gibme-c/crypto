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
// fuzz_target_vrf.cpp
//
// Exercises both VRF variants: native Crypto::VRF and spec-compliant
// Crypto::VRF::RFC9381 (ECVRF-EDWARDS25519-SHA512-ELL2).
//
// Paths exercised:
//   1. vrf_proof_t byte ctor with adversarial bytes
//   2. vrf_rfc9381_proof_t byte ctor with adversarial bytes
//   3. Native VRF prove + verify round-trip + tamper + wrong-pk
//   4. RFC 9381 VRF prove + verify round-trip
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_vrf(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. vrf_proof_t byte ctor --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 200);
            const auto buf = r.read_vector(n);
            const vrf_proof_t p(buf);
            (void)p;
        });

    // -- 2. vrf_rfc9381_proof_t byte ctor --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 200);
            const auto buf = r.read_vector(n);
            const vrf_rfc9381_proof_t p(buf);
            (void)p;
        });

    // -- 3. Native VRF round-trip + tamper + wrong-pk --
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

            const size_t alpha_len = r.read_u8_range(0, 64);
            const auto alpha = r.read_vector(alpha_len);

            auto [proof, beta] = Crypto::VRF::prove(sk, alpha);

            auto [ok, verified_beta] = Crypto::VRF::verify(pk, alpha, proof);
            if (!ok)
            {
                throw std::runtime_error("Crypto::VRF round-trip: verify rejected a fresh proof");
            }
            if (!(beta == verified_beta))
            {
                throw std::runtime_error("Crypto::VRF round-trip: verify returned a different beta from prove");
            }

            // Wrong-pk rejection: use a different secret's pubkey.
            unsigned char sk2_buf[32];
            (void)r.read_bytes(sk2_buf, 32);
            const scalar_t sk2 = scalar_t::from_bytes_reduced(sk2_buf);
            if (sk2.empty() || sk2 == sk)
            {
                return;
            }
            const public_key_t pk2 = sk2.point();
            auto [bad_ok, bad_beta] = Crypto::VRF::verify(pk2, alpha, proof);
            (void)bad_beta;
            if (bad_ok)
            {
                throw std::runtime_error("Crypto::VRF verify accepted a proof under the wrong public key");
            }
        });

    // -- 4. RFC 9381 VRF round-trip --
    //
    // RFC 9381 takes a secret_key_t (32-byte raw seed) instead of a
    // pre-derived scalar. Build one from fuzzer bytes and use its
    // cached public key.
    //
    // IMPORTANT: the public key MUST be read from sk.point() — it is
    // NOT `scalar_t::from_rfc8032_seed(seed).point()`. secret_key_t's
    // load_hook() first applies SHA-512 to the seed and passes the
    // UPPER half of the hash (not the raw seed) into from_rfc8032_seed
    // per RFC 8032 §5.1.5. Re-deriving the public key from the raw
    // seed bypasses that step and gives the wrong pubkey. See
    // src/types/secret_key_t.cpp::load_hook().
    catch_safe(
        [&]
        {
            unsigned char seed_buf[32];
            (void)r.read_bytes(seed_buf, 32);
            const secret_key_t sk(std::vector<unsigned char>(seed_buf, seed_buf + 32));
            const public_key_t pk = sk.point();

            const size_t alpha_len = r.read_u8_range(0, 64);
            const auto alpha = r.read_vector(alpha_len);

            auto [proof, beta] = Crypto::VRF::RFC9381::prove(sk, alpha);

            auto [ok, verified_beta] = Crypto::VRF::RFC9381::verify(pk, alpha, proof);
            if (!ok)
            {
                throw std::runtime_error("Crypto::VRF::RFC9381 round-trip: verify rejected a fresh proof");
            }
            if (!(beta == verified_beta))
            {
                throw std::runtime_error(
                    "Crypto::VRF::RFC9381 round-trip: verify returned a different beta from prove");
            }
        });
}
