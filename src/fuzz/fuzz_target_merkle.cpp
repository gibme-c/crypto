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
// fuzz_target_merkle.cpp
//
// Exercises RFC 6962 Merkle tree primitives:
//   - root_hash(leaves)
//   - tree_branch(leaves, leaf_index) + root_hash_from_branch
//   - tree_depth
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

extern "C" void fuzz_one_merkle(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // Build a random leaf vector from the fuzzer bytes.
    const size_t leaf_count = r.read_u8_range(0, 16);
    std::vector<hash_t> leaves(leaf_count);
    for (size_t i = 0; i < leaf_count; ++i)
    {
        unsigned char buf[32];
        (void)r.read_bytes(buf, 32);
        leaves[i] = hash_t(std::vector<unsigned char>(buf, buf + 32));
    }

    // -- 1. root_hash --
    catch_safe(
        [&]
        {
            const hash_t root = Crypto::Merkle::root_hash(leaves);
            (void)root;
        });

    // -- 2. tree_depth --
    catch_safe(
        [&]
        {
            const size_t d = Crypto::Merkle::tree_depth(leaves.size());
            (void)d;
        });

    // -- 3. tree_branch + root_hash_from_branch round-trip --
    if (leaves.empty())
    {
        return;
    }
    catch_safe(
        [&]
        {
            const size_t leaf_index = r.read_u8_range(0, static_cast<uint8_t>(leaves.size() - 1));

            const Crypto::Merkle::merkle_branch_t br = Crypto::Merkle::tree_branch(leaves, leaf_index);

            const hash_t expected_root = Crypto::Merkle::root_hash(leaves);
            const hash_t recomputed = Crypto::Merkle::root_hash_from_branch(br.siblings, leaves[leaf_index], br.path);

            if (!(recomputed == expected_root))
            {
                throw std::runtime_error(
                    "Merkle tree_branch/root_hash_from_branch round-trip did not reproduce the root");
            }

            // NOTE: a "flip the path bit and verify rejection" assertion
            // would be nice, but it is NOT a valid invariant when two
            // leaves hash to the same value at a given level. RFC 6962
            // uses hash_node(A, B) = SHA3(0x01 || A || B), which is
            // order-sensitive only when A != B. For fuzzer inputs where
            // all leaves happen to be identical (reachable when the fuzz
            // buffer is short and read_bytes zero-pads), every internal
            // node has sibling == accumulator, so left/right swaps at
            // any level produce hash_node(X, X) on both sides and the
            // root stays stable. The library is correct; a tamper
            // assertion would be too strong for general fuzz input. A
            // targeted test that ensures all leaves are distinct belongs
            // in src/test.cpp::test_merkle, not in the fuzz harness.
        });
}
