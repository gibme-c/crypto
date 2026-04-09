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
// fuzz_target_entropy.cpp
//
// Exercises the entropy_t deserialization surface. entropy_t is the BIP-39
// root entropy type (128 or 256 bits) that feeds mnemonic phrase encoding
// and HD key derivation. Its deserialization paths are:
//
//   1. entropy_t(std::vector<unsigned char>) — byte-vector ctor
//   2. entropy_t(std::string)                — string ctor
//   3. entropy_t::bits()                     — size introspection
//   4. entropy_t::timestamp()                — embedded creation timestamp
//
// Mnemonic decoding (Mnemonics::decode / entropy_t::recover) is covered by
// fuzz_target_mnemonics.cpp, not here.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_entropy(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. ctor from std::vector<unsigned char> --
    // entropy_t is a SerializablePod<32>, so vector-based construction
    // with wrong length must SAFE-throw.
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 64);
            const std::vector<unsigned char> v = r.read_vector(n);
            entropy_t e(v);
            (void)e.bits();
            (void)e.timestamp();
        });

    // -- 2. ctor from std::string --
    catch_safe(
        [&]
        {
            const size_t n = r.read_u8_range(0, 128);
            const auto buf = r.read_vector(n);
            const std::string str(reinterpret_cast<const char *>(buf.data()), buf.size());
            entropy_t e(str);
            (void)e.bits();
            (void)e.timestamp();
        });
}
