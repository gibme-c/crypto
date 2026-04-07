# Merkle Tree

A binary hash tree for compact set membership proofs, following [RFC 6962][rfc6962]
(Certificate Transparency). Given N leaf hashes, an inclusion proof for any leaf is only
`O(log N)` hashes -- much smaller than transmitting all N leaves.

**Namespace**: `Crypto::Merkle`
**Header**: [`merkle.h`](merkle.h)
**References**: [Merkle, 1987][merkle-paper], [RFC 6962 §2.1][rfc6962]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Binary hash trees |
| [Domain separation](#domain-separation) | 0x00/0x01 leaf vs internal tags |
| [Tree shape](#tree-shape) | RFC 6962 recursive construction |
| [API](#api) | Root hash, branch extraction, membership verification |
| [Use Cases](#use-cases) | Transaction inclusion, certificate transparency |
| [References](#references) | Papers and standards |

---

## How It Works (ELI5)

A Merkle tree takes a list of data items (leaves), hashes each one, then repeatedly
hashes pairs of hashes together until a single **root hash** remains. To prove that
a particular leaf belongs to the tree, you only need to provide the sibling hashes
along the path from the leaf to the root (the "inclusion path" or "branch"). The verifier
re-hashes up the tree from the leaf and checks whether the result matches the known
root -- if it does, the leaf is in the set.

```
              root
             /    \
           h01    h23
          /   \  /   \
         h0   h1 h2   h3      <- leaf hashes
```

---

## Domain separation

Per [RFC 6962 §2.1][rfc6962], leaves and internal nodes live in **disjoint hash
domains**. Each leaf is hashed with a `0x00` prefix byte before it enters the tree, and
each internal node concatenates its two children behind a `0x01` prefix byte:

```
hash_leaf(L)    = SHA3-256(0x00 || L)        // 33-byte pre-image
hash_node(A, B) = SHA3-256(0x01 || A || B)   // 65-byte pre-image
```

Without these tag bytes, an attacker could present a 64-byte concatenation of two
legitimate internal children as a "leaf" in a smaller tree and forge a shorter
inclusion path resolving to the same root -- a classic second-preimage attack on an untagged
Merkle tree. The 0x00/0x01 tags make leaf and internal pre-images structurally
disjoint (33 bytes versus 65 bytes, with different leading bytes), so no leaf hash
can ever collide with any internal-node hash regardless of input choice.

> **Important boundary detail.** A 1-leaf tree's root is `hash_leaf(L)`, **not** the
> raw leaf `L`. Equivalently, `root_hash_from_branch({}, leaf)` returns
> `hash_leaf(leaf)`. If the boundary returned the raw leaf, any 32-byte value would
> trivially be the "root of a 1-leaf tree containing itself," and an attacker could
> claim any hash as a legitimate Merkle commitment. Tagging the leaf at the boundary
> closes that vector.

---

## Tree shape

Construction follows the recursive RFC 6962 definition for any leaf count `N`:

```
MTH({})    = hash_t{}                                       // 32 zero bytes (sentinel)
MTH({L})   = hash_leaf(L)
MTH(D[n])  = hash_node(MTH(D[0:k]), MTH(D[k:n]))            for n > 1
             where k = largest power of 2 strictly less than n
```

Because `k` is the largest pow-2 *strictly less than* `n`, the left subtree is always
a perfect power-of-2 tree and the right subtree absorbs the remainder. For
non-power-of-2 leaf counts the tree is unbalanced on the right spine, so leaves on
the right may sit at shallower depths than leaves on the left. This is why
`tree_branch` requires a leaf index and why there is a per-leaf
`tree_depth(count, leaf_index)` overload alongside the "maximum depth"
`tree_depth(count)`. The leaf's depth is also implicit in the returned branch:
`merkle_branch_t::siblings.size()` always equals the leaf's depth.

### Branch representation

```
siblings[0]     -- deepest sibling (paired with the leaf itself at level 0)
siblings.back() -- topmost sibling (paired with the near-root accumulator)
path bit i      -- 0 if the leaf is on the LEFT at level i, 1 if on the RIGHT
```

This deepest-first ordering matches the bottom-up reconstruction loop in
`root_hash_from_branch` and the standard Merkle-literature convention.

---

## API

```cpp
// Build the tree root from a set of leaf hashes (RFC 6962 MTH).
auto root = Crypto::Merkle::root_hash(leaf_hashes);

// Extract an inclusion proof for a specific leaf.
auto branch = Crypto::Merkle::tree_branch(leaf_hashes, leaf_index);

// Verify membership: reconstruct the root from a leaf + branch.
auto reconstructed = Crypto::Merkle::root_hash_from_branch(
    branch.siblings, leaf_hashes[leaf_index], branch.path);
bool member = (reconstructed == root);

// Maximum depth in an N-leaf tree (== ceil(log2(N)) for N >= 1).
auto max_depth = Crypto::Merkle::tree_depth(leaf_hashes.size());

// Depth of a specific leaf (varies in non-power-of-2 trees).
auto leaf_depth = Crypto::Merkle::tree_depth(leaf_hashes.size(), leaf_index);
```

`tree_branch` throws `std::invalid_argument` for empty inputs or out-of-range
`leaf_index`. The 1-leaf case returns `{siblings={}, path=0}`; feeding the
empty branch into `root_hash_from_branch` yields `hash_leaf(leaf)`, which matches
`root_hash({leaf})`.

---

## Use Cases

- **Transaction inclusion proofs** -- prove a specific transaction was included in a
  block by providing the Merkle branch (O(log N) hashes) instead of the entire block.
- **Certificate transparency** -- append-only logs where clients can verify their
  certificate was included without downloading the full log. RFC 6962 is the
  Certificate Transparency standard.
- **Data integrity** -- any scenario where a large dataset is summarized by a single
  root hash, and you need to prove membership of individual elements.

---

## References

| Topic | Link |
|-------|------|
| Merkle hash trees | [Merkle, 1987][merkle-paper] |
| Certificate Transparency MTH definition | [RFC 6962 §2.1][rfc6962] |

[merkle-paper]: https://link.springer.com/chapter/10.1007/3-540-48184-2_32
[rfc6962]: https://datatracker.ietf.org/doc/html/rfc6962#section-2.1
