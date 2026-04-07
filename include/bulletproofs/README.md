# Bulletproofs

The original Bulletproof range proof. Given a Pedersen commitment `C`, proves
that the committed value lies in `[0, 2^N)` without revealing it. The proof size
is logarithmic in the bit-length N.

Multiple values can be aggregated into a single proof with sub-linear size
growth -- proving M values costs only `O(log(M*N))` group elements instead of
`M * O(log N)`.

**Namespace**: `Crypto::RangeProofs::Bulletproofs`
**Header**: [`bulletproofs.h`](bulletproofs.h)
**Reference**: [Bunz et al., 2018 (ePrint 2017/1066)][bp-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Range proofs as extra seals on envelopes |
| [API](#api) | Prove, verify, and batch-verify |
| [Proof Sizes](#proof-sizes) | Size by aggregation count |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

A Pedersen commitment hides an amount inside an opaque envelope (see the
[RingCT module](../ringct/README.md)). But hiding alone is not enough -- someone
could commit to a negative value and effectively create money out of thin air.

A **range proof** is an additional seal on the envelope that says: "I promise
what's inside is between $0 and $2^64" -- without revealing the actual amount.
The math guarantees that no valid proof can exist for a value outside the range.

Bulletproofs achieve this by encoding each bit of the value and proving (via an
inner product argument) that they are all 0 or 1, and that they reconstruct the
committed value. The proof is logarithmic in the number of bits, producing
compact proofs of around 674 bytes for a single 64-bit value.

```
+--------------------------------------+
|        Bulletproof Structure         |
|                                      |
|   A, S     vector commitments        |
|   T1, T2   polynomial coefficients   |
|   taux, mu blinding responses        |
|   L[], R[] IPA folding rounds        |  <- log2(M*N) pairs
|   g, h     final generator scalars   |
|   t        evaluated inner product   |
|                                      |
|   Proof size: ~674 bytes (M=1, N=64) |
+--------------------------------------+
```

---

## API

```cpp
// amounts:          vector of uint64_t values to prove are in [0, 2^64)
// blinding_factors: one random blinding_factor_t per amount (used in the commitment)
// Returns:          (proof, commitments) where commitments[i] = blindings[i]*G + amounts[i]*H
auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove(
    amounts, blinding_factors);

// Verify a single proof against its commitments
bool valid = Crypto::RangeProofs::Bulletproofs::verify(proof, commitments);

// Batch-verify multiple independent proofs in a single MSM
// (much faster than verifying each one individually)
bool all_valid = Crypto::RangeProofs::Bulletproofs::verify(
    {proof1, proof2, proof3},
    {commitments1, commitments2, commitments3});
```

---

## Proof Sizes

| Values (M) | Proof Size |
|-----------|------------|
| 1         | ~674 B     |
| 2         | ~738 B     |
| 4         | ~802 B     |
| 8         | ~866 B     |
| 16        | ~930 B     |

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 12-14 | Bulletproofs |

---

## References

| Topic | Link |
|-------|------|
| Bulletproofs | [Bunz et al., 2018 (ePrint 2017/1066)][bp-paper] |
| Inner product arguments | [Bootle et al., 2016][ipa-paper] |
| Pedersen commitments | [Pedersen, 1991][pedersen-paper] |

[bp-paper]: https://eprint.iacr.org/2017/1066
[ipa-paper]: https://eprint.iacr.org/2016/263
[pedersen-paper]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9
