# Triptych

Triptych achieves **logarithmic signature size** in the ring size N. While CLSAG
and MLSAG grow linearly (32 bytes per ring member), Triptych grows as
`O(log N)`. This makes very large anonymity sets practical -- a ring of 1024
members costs only ~992 bytes instead of the ~32,800 that CLSAG would need.

**Namespace**: `Crypto::RingSignature::Triptych`
**Header**: [`triptych.h`](triptych.h)
**Reference**: [Noether, 2020 (ePrint 2020/018)][triptych-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Logarithmic ring signatures explained with a library of books |
| [API](#api) | Ring signature generation and verification |
| [Ring Size Constraint](#ring-size-constraint) | Power-of-2 requirement |
| [Use Cases](#use-cases) | Large anonymity sets |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Like CLSAG, MLSAG, and Borromean, Triptych is a **ring signature**: you
prove that you know the secret key for *one* of N public keys without
revealing which one. Same lineup-of-suspects idea, same key image for
double-spend prevention. What makes Triptych special is **how it scales**.

With CLSAG or MLSAG, doubling the ring roughly doubles the signature. If
you want 1024 decoys, you pay 1024 decoys' worth of bytes. That's fine for
rings of 11 or 16 but quickly gets ugly for big anonymity sets. Triptych
uses a clever trick where the signature grows with the **logarithm** of
the ring size instead of the ring size itself.

Think of a **library with N books** where you want to prove "I know a
secret about one of these books" without saying which. CLSAG is like
writing a little note for every single book -- 1024 books means 1024
notes. Triptych instead walks down a decision tree: "it's in the left
half... no wait, it's in the right half of the left half... no wait..."
Each step only takes a few bytes, and you only need log2(N) steps. Double
the library from 512 to 1024 books and you only add **one more step**,
not another 512 notes.

```
  CLSAG size:     32 + 32*N bytes              (grows with N)
  Triptych size:  352 + 64*log2(N) bytes       (grows with log N)

  N=16   CLSAG   544 B   Triptych  608 B     (CLSAG wins by a bit)
  N=256  CLSAG  8224 B   Triptych  864 B     (Triptych wins huge)
  N=1024 CLSAG 32800 B   Triptych  992 B     (Triptych wins enormously)
```

The trade-offs: Triptych's ring size **must be a power of 2** (4, 8, 16,
32, ...) because of the way the decomposition works. Pad with dummy keys
if your decoy set isn't the right shape. Triptych also **always requires
commitment binding** -- there's no "plain" variant without Pedersen
commitments, so it's really designed for confidential transactions, not
generic anonymous authentication.

---

```
+--------------------------------------------------------------+
|                   Triptych Signature                         |
|                                                              |
|   Ring size N = n^m (must be power of 2, default n=2)        |
|   Decompose signer index l into m digits base n:             |
|     l = l0 + l1*n + l2*n^2 + ... + l_{m-1}*n^{m-1}         |
|                                                              |
|   Signature:                                                 |
|     A, B, C, D  commitment points         (4 x 32 B)        |
|     X[], Y[]    per-digit auxiliary pts    (2m x 32 B)       |
|     f[][]       response matrix           (m x (n-1) x 32 B)|
|     zA, zC, z   final response scalars    (3 x 32 B)        |
|     + commitment_image + pseudo_commitment (64 B)            |
|                                                              |
|   Total: ~352 + 64*log2(N) bytes                             |
|                                                              |
|   N=64   -> ~736 B     (vs ~2,080 B CLSAG)                  |
|   N=256  -> ~864 B     (vs ~8,224 B CLSAG)                  |
|   N=1024 -> ~992 B     (vs ~32,800 B CLSAG)                 |
+--------------------------------------------------------------+
```

---

## API

Triptych **requires** Pedersen commitment binding (no commitment-free variant):

```cpp
// Sign (all parameters required -- Triptych always uses commitment binding)
auto [ok, sig] = Crypto::RingSignature::Triptych::generate_ring_signature(
    digest,                // transaction hash
    secret_key,            // one-time secret key for the real output
    ring_public_keys,      // all keys in the ring (must be power-of-2 count)
    input_blinding,        // blinding factor of the real input commitment
    ring_commitments,      // Pedersen commitments for all ring members
    pseudo_blinding,       // blinding factor for the pseudo-commitment
    pseudo_commitment);    // reblinded commitment for balance checking

// Triptych uses the alternate key image form: I = (1/x) * U
// This must be computed with generate_key_image_v2, NOT generate_key_image.
auto key_image = Crypto::generate_key_image_v2(secret_key);

// Verify
bool valid = Crypto::RingSignature::Triptych::check_ring_signature(
    digest, key_image, ring_public_keys, sig, ring_commitments);
```

**Important:** Triptych uses the alternate key image form `I = (1/x) * U`.
You must use `Crypto::generate_key_image_v2(secret_key)` instead of the
standard `Crypto::generate_key_image(public_key, secret_key)` used by
CLSAG, MLSAG, and Borromean.

---

## Ring Size Constraint

The ring size N must be a power of 2 (4, 8, 16, 32, 64, 128, 256, ...). If the
available decoy set isn't a power of 2, pad with dummy keys to the next power.

---

## Use Cases

- **Large anonymity sets** -- practical ring sizes of 128 or 256 (compared to
  [CLSAG's](../clsag/README.md) typical 11-16) with comparable or smaller signatures

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 10-11 | Triptych |

---

## References

| Topic | Link |
|-------|------|
| Triptych logarithmic ring signatures | [Noether, 2020 (ePrint 2020/018)][triptych-paper] |

[triptych-paper]: https://eprint.iacr.org/2020/018
