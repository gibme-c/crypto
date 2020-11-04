// Copyright (c) 2020, Brandon Lehmann
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

#ifndef CRYPTO_MERKLE_H
#define CRYPTO_MERKLE_H

#include <types/crypto_hash_t.h>

namespace Crypto::Merkle
{
    /**
     * Generates the merkle root hash for the given set of hashes
     * @param hashes
     * @return
     */
    crypto_hash_t root_hash(const std::vector<crypto_hash_t> &hashes);

    /**
     * Generates the merkle root hash from the given set of merkle branches and the supplied leaf
     * following the provided path (0 or 1)
     * @param branches
     * @param depth
     * @param leaf
     * @param path
     * @return
     */
    crypto_hash_t root_hash_from_branch(
        const std::vector<crypto_hash_t> &branches,
        size_t depth,
        const crypto_hash_t &leaf,
        const size_t &path = 0);

    /**
     * Generates the merkle tree branches for the given set of hashes
     * @param hashes
     */
    std::vector<crypto_hash_t> tree_branch(const std::vector<crypto_hash_t> &hashes);

    /**
     * Calculates the depth of the merkle tree based on the count of elements
     * @param count
     * @return
     */
    size_t tree_depth(size_t count);
} // namespace Crypto::Merkle


#endif // CRYPTO_MERKLE_H
