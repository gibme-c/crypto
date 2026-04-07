# Merkle Tree

A classic binary hash tree for compact set membership proofs. Given N leaf
hashes, a Merkle proof that a particular leaf belongs to the tree is only
`O(log N)` hashes -- much smaller than transmitting all N leaves.

**Namespace**: `Crypto::Merkle`
**Header**: [`merkle.h`](merkle.h)
**Reference**: [Merkle, 1987][merkle-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Binary hash trees |
| [API](#api) | Root hash, branch extraction, membership verification |
| [Use Cases](#use-cases) | Transaction inclusion, certificate transparency |
| [References](#references) | Papers |

---

## How It Works (ELI5)

A Merkle tree takes a list of data items (leaves), hashes each one, then
repeatedly hashes pairs of hashes together until a single **root hash** remains.
To prove that a particular leaf belongs to the tree, you only need to provide the
sibling hashes along the path from the leaf to the root (the "branch"). The
verifier rehashes up the tree and checks whether the result matches the known
root -- if it does, the leaf is in the set.

```
              root
             /    \
           h01    h23
          /   \  /   \
         h0   h1 h2   h3      <- leaf hashes
```

---

## API

```cpp
// Build the tree root from a set of leaf hashes
auto root = Crypto::Merkle::root_hash(leaf_hashes);

// Extract a membership proof (branch) for a specific leaf
auto branch = Crypto::Merkle::tree_branch(leaf_hashes);
auto depth = Crypto::Merkle::tree_depth(leaf_hashes.size());

// Verify membership: reconstruct the root from a leaf + branch
auto reconstructed = Crypto::Merkle::root_hash_from_branch(
    branch, depth, leaf_hash, path_index);
bool member = (reconstructed == root);
```

---

## Use Cases

- **Transaction inclusion proofs** -- prove a specific transaction was included
  in a block by providing the Merkle branch (O(log N) hashes) instead of the
  entire block
- **Certificate transparency** -- append-only logs where clients can verify
  their certificate was included without downloading the full log
- **Data integrity** -- any scenario where a large dataset is summarized by a
  single root hash, and you need to prove membership of individual elements

---

## References

| Topic | Link |
|-------|------|
| Merkle hash trees | [Merkle, 1987][merkle-paper] |

[merkle-paper]: https://link.springer.com/chapter/10.1007/3-540-48184-2_32
