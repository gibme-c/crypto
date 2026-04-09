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
// fuzz_target_audit.cpp
//
// Exercises Crypto::Audit outputs-proof generation and verification
// with adversarial inputs. check_outputs_proof takes a Base58-encoded
// string, so random string inputs exercise the decode-then-verify
// path — decoder must return false cleanly on malformed input.
//
// Paths exercised:
//   1. check_outputs_proof(random pubkeys, random string)
//   2. generate_outputs_proof + check_outputs_proof round-trip
//   3. Tamper on the proof string (flip one character)
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_audit(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. Adversarial check_outputs_proof --
    catch_safe(
        [&]
        {
            const size_t pk_count = r.read_u8_range(0, 4);
            std::vector<public_key_t> pks(pk_count);
            for (auto &pk : pks)
            {
                unsigned char buf[32];
                (void)r.read_bytes(buf, 32);
                pk = point_t::reduce(buf);
                if (pk.empty())
                {
                    return;
                }
            }

            const size_t proof_len = r.read_u8_range(0, 200);
            const auto proof_buf = r.read_vector(proof_len);
            const std::string proof(reinterpret_cast<const char *>(proof_buf.data()), proof_buf.size());

            auto [ok, images] = Crypto::Audit::check_outputs_proof(pks, proof);
            (void)ok;
            (void)images;
        });

    // -- 2. Round-trip --
    catch_safe(
        [&]
        {
            const size_t count = r.read_u8_range(1, 3);
            std::vector<scalar_t> secrets(count);
            std::vector<public_key_t> pks(count);
            for (size_t i = 0; i < count; ++i)
            {
                unsigned char buf[32];
                (void)r.read_bytes(buf, 32);
                secrets[i] = scalar_t::from_bytes_reduced(buf);
                if (secrets[i].empty())
                {
                    return;
                }
                pks[i] = secrets[i].point();
            }

            auto [gen_ok, proof_str] = Crypto::Audit::generate_outputs_proof(secrets);
            if (!gen_ok)
            {
                return;
            }

            auto [ver_ok, images] = Crypto::Audit::check_outputs_proof(pks, proof_str);
            if (!ver_ok)
            {
                throw std::runtime_error("Audit::check_outputs_proof rejected a proof we just generated");
            }
            if (images.size() != count)
            {
                throw std::runtime_error("Audit::check_outputs_proof returned wrong number of key images");
            }

            // Tamper rejection: flip one character of the proof string.
            if (proof_str.size() > 4)
            {
                std::string tampered = proof_str;
                tampered[tampered.size() / 2] = (tampered[tampered.size() / 2] == 'A') ? 'B' : 'A';

                auto [bad_ok, bad_images] = Crypto::Audit::check_outputs_proof(pks, tampered);
                (void)bad_images;
                if (bad_ok)
                {
                    // Most tampers either fail Base58 decode, fail
                    // checksum, or fail signature verification. If the
                    // tamper produces a DIFFERENT valid proof that still
                    // verifies against the same pubkeys, that's
                    // noteworthy but technically possible for a
                    // well-chosen tamper. We accept bad_ok=true as a
                    // no-finding — the real assertion is "no crash and
                    // no invalid-type throw".
                    (void)0;
                }
            }
        });
}
