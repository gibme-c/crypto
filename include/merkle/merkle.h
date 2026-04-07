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
 * @brief RFC 6962 Merkle tree construction and membership verification.
 *
 * A Merkle tree is a binary hash tree where each parent node is the hash of its two
 * children. The root commits to every leaf so membership can be proven with only the
 * sibling hashes along the path from the leaf to the root -- an O(log N) inclusion
 * path rather than the full dataset.
 *
 * ## Domain separation
 *
 * Leaves and internal nodes live in disjoint hash domains per RFC 6962 §2.1:
 *
 *   hash_leaf(L)      = SHA3-256(0x00 || L)
 *   hash_node(A, B)   = SHA3-256(0x01 || A || B)
 *
 * Without the tag bytes, an attacker could present a 64-byte concatenation of two
 * legitimate children as a "leaf" in a smaller tree and forge a shorter inclusion
 * path resolving to the same root (classic second-preimage attack). The 0x00/0x01
 * prefix makes leaf and internal pre-images non-overlapping, so no collision is
 * possible.
 *
 * ## Tree shape
 *
 * Construction follows the recursive RFC 6962 definition for any leaf count N:
 *
 *   MTH({})   = hash_t{}   (32 zero bytes -- empty sentinel)
 *   MTH({L})  = hash_leaf(L)
 *   MTH(D[n]) = hash_node(MTH(D[0:k]), MTH(D[k:n])) for n > 1
 *
 * where k is the largest power of 2 strictly less than n. This yields perfect power-of-2
 * left subtrees at every recursion level; the right subtree absorbs the remainder. For
 * non-power-of-2 trees, different leaves end up at different depths (the tree is
 * unbalanced on the right spine), which is why tree_branch requires a leaf index and why
 * merkle_branch_t carries its own depth.
 *
 * ## Branch representation
 *
 *   siblings[0]     -- deepest sibling (paired with the leaf itself at level 0)
 *   siblings.back() -- topmost sibling (paired with the near-root node)
 *   path bit i      -- 0 if the leaf is on the LEFT at level i, 1 if on the RIGHT
 *
 * This "deepest-first" convention matches the bottom-up build order in
 * root_hash_from_branch and is the standard Merkle-literature convention.
 */

#ifndef CRYPTO_MERKLE_H
#define CRYPTO_MERKLE_H

#include <types/hash_t.h>

namespace Crypto::Merkle
{
    /**
     * A Merkle inclusion proof for a single leaf.
     *
     * The reconstruction loop in root_hash_from_branch() walks siblings[] from index 0
     * (deepest, paired with the leaf) to the top, using path bits to decide which side
     * the current accumulator sits on at each level. The depth of the leaf in the tree
     * is simply siblings.size().
     *
     * @note path is a bitmask, so the maximum representable depth is the bit width of
     * size_t (64 on 64-bit platforms). At one bit per level this caps the tree at
     * 2^64 leaves, far beyond any practical limit; tree_branch() throws on overflow.
     */
    struct merkle_branch_t
    {
        /** Sibling hashes along the path, deepest first (siblings[0] pairs with the leaf). */
        std::vector<hash_t> siblings;

        /** Path bitmask: bit i = 0 if the leaf is LEFT at level i, 1 if RIGHT. */
        size_t path;
    };

    /**
     * Computes the Merkle root hash from a set of leaf hashes (RFC 6962 §2.1).
     *
     * Input leaves are re-hashed with the 0x00 leaf tag before folding, and internal
     * nodes are hashed with the 0x01 tag. An empty input returns the zero sentinel.
     *
     * @param hashes the leaf-level hashes to build the tree from
     * @return the root hash that commits to all leaves
     */
    hash_t root_hash(const std::vector<hash_t> &hashes);

    /**
     * Recomputes the Merkle root from a branch proof and a leaf.
     *
     * Walks siblings[] from deepest (siblings[0], paired with the leaf) to the top,
     * using the path bitmask to decide left/right placement at each level. Always
     * applies the 0x00 leaf tag to @p leaf before the first combine step -- a branch
     * of depth 0 returns hash_leaf(leaf), matching root_hash({leaf}).
     *
     * @param siblings deepest-first sibling hashes (siblings[0] is paired with the leaf)
     * @param leaf the raw leaf hash to verify membership for
     * @param path bitmask; bit i = 0 if the leaf is LEFT at level i, 1 if RIGHT
     * @return the reconstructed root hash
     */
    hash_t root_hash_from_branch(const std::vector<hash_t> &siblings, const hash_t &leaf, size_t path = 0);

    /**
     * Extracts the inclusion proof for a specific leaf.
     *
     * For a 1-leaf tree returns {siblings={}, path=0}; the caller feeds the leaf into
     * root_hash_from_branch() which returns hash_leaf(leaf) -- symmetric with
     * root_hash({leaf}).
     *
     * @note Cost: this routine recomputes the sibling subtree roots on demand, so a
     * single call costs O(N) hashes for an N-leaf tree (the work is dominated by
     * hashing the half of the tree that does not contain @p leaf_index). For bulk
     * proof generation across many leaves an amortized O(N log N) implementation
     * would precompute the layered subtree roots once -- not currently provided
     * because the library has no caller that demands it. Open a follow-up if you
     * need bulk inclusion proofs at scale (Certificate-Transparency-style workloads).
     *
     * @param hashes the leaf-level hashes that form the tree
     * @param leaf_index zero-based index of the leaf to prove
     * @return a merkle_branch_t containing the siblings and path bits
     * @throws std::invalid_argument if @p hashes is empty, @p leaf_index is out of
     *         range, or the resulting tree depth would not fit in the path bitmask
     */
    merkle_branch_t tree_branch(const std::vector<hash_t> &hashes, size_t leaf_index);

    /**
     * Returns the maximum depth of any leaf in an N-leaf RFC 6962 tree.
     *
     * Equal to ceil(log2(count)) for count >= 1, and 0 for count == 0. For non-power-of-2
     * trees the rightmost leaves may sit at shallower depths than this maximum; use the
     * per-leaf overload if you need the exact depth of a specific leaf.
     *
     * @param count the number of leaves in the tree
     * @return ceil(log2(count)) for count >= 1; 0 for count == 0
     */
    size_t tree_depth(size_t count);

    /**
     * Returns the depth of a specific leaf in an N-leaf RFC 6962 tree.
     *
     * In an unbalanced (non-power-of-2) tree, leaves on the right spine sit at shallower
     * depths than the leftmost leaves. This overload walks the recursive split to find
     * the exact depth of @p leaf_index.
     *
     * @param count the number of leaves in the tree
     * @param leaf_index zero-based index of the leaf
     * @return the depth of @p leaf_index (number of sibling hashes between it and the root)
     * @throws std::invalid_argument if @p leaf_index >= @p count
     */
    size_t tree_depth(size_t count, size_t leaf_index);
} // namespace Crypto::Merkle


#endif // CRYPTO_MERKLE_H
