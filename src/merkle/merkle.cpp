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
 * @brief Merkle tree construction, branch extraction, and root verification using SHA-3.
 */

#include <merkle/merkle.h>

static inline std::vector<hash_t> slice(const std::vector<hash_t> &values, size_t start, size_t count)
{
    std::vector<hash_t> results;

    results.reserve(count);

    for (size_t i = start; i < start + count; i++)
    {
        results.push_back(values[i]);
    }

    return results;
}


namespace Crypto::Merkle
{
    hash_t root_hash(const std::vector<hash_t> &hashes)
    {
        hash_t root_hash;

        const auto count = hashes.size();

        if (count == 0)
        {
            root_hash = hash_t();
        }
        else if (count == 1)
        {
            root_hash = hashes[0];
        }
        else if (count == 2)
        {
            root_hash = hash_t::sha3(hashes);
        }
        else
        {
            // Round down to the largest power of 2 <= count
            auto cnt = count - 1;

            for (size_t i = 1; i < 8 * sizeof(size_t); i <<= 1)
            {
                cnt |= cnt >> i;
            }

            cnt &= ~(cnt >> 1);

            // Hash excess leaves pairwise into the bottom layer, then fold upward
            const auto rounds = (2 * cnt) - count;

            std::vector<hash_t> temp_hashes = slice(hashes, 0, cnt);

            for (size_t i = rounds, j = rounds; j < cnt; i += 2, ++j)
            {
                temp_hashes[j] = hash_t::sha3(slice(hashes, i, 2));
            }

            // Iteratively combine pairs until 2 remain
            while (cnt > 2)
            {
                cnt >>= 1;

                for (size_t i = 0, j = 0; j < cnt; i += 2, ++j)
                {
                    temp_hashes[j] = hash_t::sha3(slice(temp_hashes, i, 2));
                }
            }

            root_hash = hash_t::sha3(slice(temp_hashes, 0, 2));
        }

        return root_hash;
    }

    hash_t root_hash_from_branch(
        const std::vector<hash_t> &branches,
        size_t tree_depth,
        const hash_t &leaf,
        const size_t &path)
    {
        hash_t root_hash;

        if (tree_depth == 0)
        {
            root_hash = leaf;
        }
        else
        {
            std::vector<hash_t> buf;

            buf.resize(2);

            bool from_leaf = true;

            hash_t *leaf_path, *branch_path;

            while (tree_depth > 0)
            {
                --tree_depth;

                if ((path >> tree_depth) & 1)
                {
                    leaf_path = &buf[1];

                    branch_path = &buf[0];
                }
                else
                {
                    leaf_path = &buf[0];

                    branch_path = &buf[1];
                }

                if (from_leaf)
                {
                    *leaf_path = leaf;

                    from_leaf = false;
                }
                else
                {
                    *leaf_path = hash_t::sha3(buf);
                }

                *branch_path = branches[tree_depth];
            }

            root_hash = hash_t::sha3(buf);
        }

        return root_hash;
    }

    std::vector<hash_t> tree_branch(const std::vector<hash_t> &hashes)
    {
        if (hashes.size() < 2)
        {
            throw std::invalid_argument("tree_branch requires at least 2 hashes");
        }

        const auto count = hashes.size();

        size_t cnt = 1;

        auto depth = tree_depth(count);

        std::vector<hash_t> branches(depth);

        for (size_t i = sizeof(size_t) << 2; i > 0; i >>= 1)
        {
            if (cnt << i <= count)
            {
                cnt <<= i;
            }
        }

        const auto rounds = (2 * cnt) - count;

        std::vector<hash_t> temp_hashes;

        temp_hashes.resize(cnt - 1);

        for (size_t i = rounds, j = rounds - 1; j < cnt - 1; i += 2, ++j)
        {
            temp_hashes[j] = hash_t::sha3(slice(hashes, i, 2));
        }

        while (depth > 0)
        {
            cnt >>= 1;

            --depth;

            branches[depth] = temp_hashes[0];

            if (cnt > 1)
            {
                for (size_t i = 1, j = 0; j < cnt - 1; i += 2, ++j)
                {
                    temp_hashes[j] = hash_t::sha3(slice(temp_hashes, i, 2));
                }
            }
        }

        return branches;
    }

    size_t tree_depth(size_t count)
    {
        size_t depth = 0;

        for (size_t i = sizeof(size_t) << 2; i > 0; i >>= 1)
        {
            if (count >> i > 0)
            {
                count >>= i;

                depth += i;
            }
        }

        return depth;
    }
} // namespace Crypto::Merkle
