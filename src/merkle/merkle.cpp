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
 * @file merkle.cpp
 * @brief RFC 6962 Merkle tree with 0x00/0x01 leaf/internal domain separation.
 *
 * See include/merkle/merkle.h for the full contract. This implementation is a direct
 * transcription of the RFC 6962 §2.1 recursive definition on top of SHA3-256 via the
 * hash_t::sha3 template overload.
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <helpers/math_helpers.h>
#include <merkle/merkle.h>
#include <stdexcept>

namespace
{
    // hash_t is a SerializablePod<32>; the underlying byte array is exactly 32 bytes.
    // We rely on this constant in the tag+payload buffers below.
    constexpr size_t kHashBytes = 32;

    // RFC 6962 §2.1 leaf tag. Every leaf hash that enters the tree is first re-hashed
    // with a 0x00 prefix byte. Without the tag, a 64-byte value equal to the
    // concatenation of two legitimate internal children could be presented as a
    // "leaf" and forge a shorter inclusion path to the same root (classic
    // second-preimage attack on an untagged Merkle tree). With the 0x00/0x01 tag
    // bytes the leaf and internal pre-images live in disjoint domains, so no leaf
    // hash can collide with any internal-node hash regardless of input choice.
    //
    // SECURITY: this function MUST be called on every leaf entering the tree, including
    // the single-leaf case in root_hash() and the leaf argument to root_hash_from_branch().
    // Forgetting to tag even one boundary re-opens the second-preimage vector at that
    // boundary.
    inline hash_t hash_leaf(const hash_t &leaf)
    {
        std::array<uint8_t, 1 + kHashBytes> buf {};

        buf[0] = 0x00;

        std::memcpy(buf.data() + 1, leaf.data(), kHashBytes);

        return hash_t::sha3(buf);
    }

    // RFC 6962 §2.1 internal-node tag. Two 32-byte children are concatenated behind a
    // 0x01 prefix byte. Combined with hash_leaf()'s 0x00 prefix this gives each
    // internal node a unique 65-byte pre-image that cannot collide with any 33-byte
    // leaf pre-image -- the structural guarantee behind RFC 6962 second-preimage
    // resistance.
    inline hash_t hash_node(const hash_t &left, const hash_t &right)
    {
        std::array<uint8_t, 1 + 2 * kHashBytes> buf {};

        buf[0] = 0x01;

        std::memcpy(buf.data() + 1, left.data(), kHashBytes);
        std::memcpy(buf.data() + 1 + kHashBytes, right.data(), kHashBytes);

        return hash_t::sha3(buf);
    }

    // Largest power of 2 strictly less than n. Only valid for n >= 2. This is the split
    // point used by the RFC 6962 recursive definition: for n leaves, the left subtree
    // covers the first k leaves and the right subtree covers the remaining (n - k),
    // where k is the largest power of 2 with k < n. The left subtree is therefore
    // always a perfect power-of-2 tree, while the right subtree absorbs the remainder
    // (which itself may be further unbalanced at the next recursion level).
    inline size_t largest_pow2_lt(size_t n)
    {
        size_t k = 1;

        while ((k << 1) < n)
        {
            k <<= 1;
        }

        return k;
    }

    // RFC 6962 Merkle Tree Hash over the range [start, start + n) of @p leaves.
    // The empty case returns the all-zero sentinel; callers that need a distinguishable
    // "no commitment" marker should check against hash_t{} explicitly.
    //
    // SECURITY: the n == 1 branch routes through hash_leaf() rather than returning the
    // raw input. If it returned the leaf verbatim, any 32-byte value X would trivially
    // be "the root of a 1-leaf tree containing X" -- letting an attacker claim any hash
    // as a legitimate merkle commitment. The 0x00 leaf tag closes that boundary vector.
    hash_t mth(const std::vector<hash_t> &leaves, size_t start, size_t n)
    {
        if (n == 0)
        {
            return hash_t();
        }

        if (n == 1)
        {
            return hash_leaf(leaves[start]);
        }

        const size_t k = largest_pow2_lt(n);

        return hash_node(mth(leaves, start, k), mth(leaves, start + k, n - k));
    }

    // Recursive inclusion-proof builder. Walks the same RFC 6962 split that mth() uses,
    // but instead of folding to a single root it emits the sibling along the path and
    // records left/right at each level.
    //
    // @p out is appended to in bottom-up order -- after the recursive call but before
    // the sibling push_back -- so out[0] ends up as the deepest sibling (paired with
    // the leaf itself at level 0) and out.back() is the topmost sibling (paired with
    // the near-root node). The path bitmask is built with the same orientation: bit
    // (out.size() - 1) before the push_back is the direction at the level we're about
    // to add.
    void tree_branch_recurse(
        const std::vector<hash_t> &leaves,
        size_t start,
        size_t n,
        size_t leaf_index,
        std::vector<hash_t> &out,
        size_t &path)
    {
        if (n <= 1)
        {
            // A subtree with 0 or 1 leaves has no siblings to contribute.
            return;
        }

        const size_t k = largest_pow2_lt(n);

        if (leaf_index < k)
        {
            // Leaf sits in the LEFT subtree at this level. Recurse there first so the
            // deeper siblings land at lower out[] indices, then append the RIGHT
            // subtree's root as the sibling at this level. path bit stays 0.
            tree_branch_recurse(leaves, start, k, leaf_index, out, path);

            out.push_back(mth(leaves, start + k, n - k));
        }
        else
        {
            // Leaf sits in the RIGHT subtree. Recurse with the index rebased into the
            // right subtree, then append the LEFT subtree's root as the sibling. Set
            // the path bit for the level we're about to add -- this is out.size()
            // *before* push_back, which is also the current bit index.
            tree_branch_recurse(leaves, start + k, n - k, leaf_index - k, out, path);

            // Guard against shift past the bit width of size_t. The tree_branch() entry
            // point already rejects oversized inputs, but we re-check here so that any
            // future caller of this internal helper cannot trigger UB silently.
            if (out.size() >= sizeof(size_t) * 8)
            {
                throw std::invalid_argument("tree_branch: tree depth exceeds path bitmask width");
            }

            path |= (static_cast<size_t>(1) << out.size());

            out.push_back(mth(leaves, start, k));
        }
    }

    // Per-leaf depth walker, mirrors tree_branch_recurse() but only counts levels.
    size_t tree_depth_recurse(size_t n, size_t leaf_index)
    {
        if (n <= 1)
        {
            return 0;
        }

        const size_t k = largest_pow2_lt(n);

        if (leaf_index < k)
        {
            return 1 + tree_depth_recurse(k, leaf_index);
        }

        return 1 + tree_depth_recurse(n - k, leaf_index - k);
    }
} // anonymous namespace


namespace Crypto::Merkle
{
    hash_t root_hash(const std::vector<hash_t> &hashes)
    {
        return mth(hashes, 0, hashes.size());
    }

    hash_t root_hash_from_branch(const std::vector<hash_t> &siblings, const hash_t &leaf, size_t path)
    {
        // Always tag the leaf, even at depth 0. A depth-0 branch (empty siblings) must
        // return hash_leaf(leaf) so that root_hash_from_branch({}, leaf) matches
        // root_hash({leaf}) -- this symmetry allows 1-leaf trees to be proven via the
        // same API as multi-leaf trees.
        hash_t current = hash_leaf(leaf);

        for (size_t i = 0; i < siblings.size(); ++i)
        {
            const bool leaf_is_right = ((path >> i) & 1u) != 0u;

            if (leaf_is_right)
            {
                // Accumulator is on the RIGHT at this level, sibling on the LEFT.
                current = hash_node(siblings[i], current);
            }
            else
            {
                // Accumulator is on the LEFT at this level, sibling on the RIGHT.
                current = hash_node(current, siblings[i]);
            }
        }

        return current;
    }

    merkle_branch_t tree_branch(const std::vector<hash_t> &hashes, size_t leaf_index)
    {
        if (hashes.empty())
        {
            throw std::invalid_argument("tree_branch: hashes must not be empty");
        }

        if (leaf_index >= hashes.size())
        {
            throw std::invalid_argument("tree_branch: leaf_index out of range");
        }

        // Reject inputs whose max depth would overflow the path bitmask. ceil(log2(N))
        // must fit in (sizeof(size_t) * 8) bits; at one bit per level this caps the
        // tree at 2^64 leaves on 64-bit platforms, far beyond any practical limit.
        if (tree_depth(hashes.size()) > sizeof(size_t) * 8)
        {
            throw std::invalid_argument("tree_branch: tree depth exceeds path bitmask width");
        }

        merkle_branch_t branch;

        branch.path = 0;

        tree_branch_recurse(hashes, 0, hashes.size(), leaf_index, branch.siblings, branch.path);

        return branch;
    }

    size_t tree_depth(size_t count)
    {
        // ceil(log2(count)) via the library's pow2 helpers. pow2_round() returns the
        // smallest power of two >= count, and calculate_base2_exponent() returns the
        // exponent. Together they yield ceil(log2(count)) with no hand-rolled log
        // loops. Matches the pattern used in triptych.cpp and bulletproofspp.cpp.
        if (count <= 1)
        {
            return 0;
        }

        const auto [ok, exponent] = Crypto::calculate_base2_exponent(Crypto::pow2_round(count));

        (void)ok; // pow2_round always returns a power of two, so the success flag is trivially true.

        return exponent;
    }

    size_t tree_depth(size_t count, size_t leaf_index)
    {
        if (leaf_index >= count)
        {
            throw std::invalid_argument("tree_depth: leaf_index out of range");
        }

        return tree_depth_recurse(count, leaf_index);
    }
} // namespace Crypto::Merkle
