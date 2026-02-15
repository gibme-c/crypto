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

/**
 * @file merkle.h
 * @brief Merkle tree construction and membership verification.
 *
 * A Merkle tree is a binary hash tree where each parent node is the hash of its two
 * children. The root hash commits to every leaf in the tree, so you can prove that a
 * particular leaf belongs to the tree by providing just the sibling hashes along the
 * path from the leaf to the root (a "Merkle branch"). This gives you O(log n)
 * membership proofs instead of transmitting the entire dataset.
 */

#ifndef CRYPTO_MERKLE_H
#define CRYPTO_MERKLE_H

#include <types/crypto_hash_t.h>

namespace Crypto::Merkle
{
    /**
     * Computes the Merkle root hash from a set of leaf hashes.
     *
     * Builds the full tree internally and returns just the root.
     *
     * @param hashes the leaf-level hashes to build the tree from
     * @return the root hash that commits to all leaves
     */
    crypto_hash_t root_hash(const std::vector<crypto_hash_t> &hashes);

    /**
     * Recomputes the Merkle root from a branch proof and a leaf.
     *
     * Given a leaf hash and the sibling hashes along the path to the root, this
     * reconstructs the root. You can compare the result against a known root to
     * verify that the leaf is indeed part of the tree.
     *
     * @param branches the sibling hashes along the path from leaf to root
     * @param depth the depth of the leaf in the tree
     * @param leaf the leaf hash to verify membership for
     * @param path a bitmask indicating left (0) or right (1) at each level
     * @return the reconstructed root hash
     */
    crypto_hash_t root_hash_from_branch(
        const std::vector<crypto_hash_t> &branches,
        size_t depth,
        const crypto_hash_t &leaf,
        const size_t &path = 0);

    /**
     * Extracts the branch (sibling) hashes needed for a Merkle membership proof.
     *
     * @param hashes the leaf-level hashes that form the tree
     * @return the branch hashes (one per tree level)
     */
    std::vector<crypto_hash_t> tree_branch(const std::vector<crypto_hash_t> &hashes);

    /**
     * Calculates the depth of a Merkle tree for a given number of leaves.
     *
     * @param count the number of leaf elements
     * @return the tree depth (number of levels above the leaves)
     */
    size_t tree_depth(size_t count);
} // namespace Crypto::Merkle


#endif // CRYPTO_MERKLE_H
