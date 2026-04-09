# Bulletproofs++

The most compact range proof in the library. Takes a fundamentally different
approach using a reciprocal argument combined with a Weighted Norm Linear
Argument (WNLA) as the inner proof system. Base-16 digit decomposition (16
digits of 4 bits each for N=64) gives the smallest proofs.

**Namespace**: `Crypto::RangeProofs::BulletproofsPP`
**Header**: [`bulletproofspp.h`](bulletproofspp.h)
**Reference**: [Habock, 2022 (ePrint 2022/510)][bppp-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Reciprocal arguments and WNLA |
| [API](#api) | Prove, verify, and batch-verify |
| [Proof Sizes](#proof-sizes) | Size and timing by aggregation count |
| [Comparison](#comparison-three-range-proof-generations) | BP vs BP+ vs BP++ |
| [Scenario](#scenario-aggregated-range-proof-for-a-transaction) | Aggregated range proof walkthrough |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Like the other Bulletproof variants, Bulletproofs++ prove that a committed value
is in `[0, 2^64)` without revealing it. The fundamental difference is the
**reciprocal argument**: instead of decomposing values into individual bits, it
uses a base-16 digit decomposition and proves membership using polynomial
evaluations over the digit set. The inner proof system is a Weighted Norm Linear
Argument (WNLA) rather than a standard IPA. Together, these techniques yield the
smallest proofs -- about 516 bytes for a single value, versus 578 (BP+) or
674 (BP).

```
+--------------------------------------+
|       Bulletproof++ Structure        |
|                                      |
|   C_l, C_r, C_o, C_s  commitments   |
|   R                    commitment    |
|   X[]  WNLA left folds              |  <- log2(M_pad) + 4 rounds
|   W[]  WNLA right folds             |
|   l[]  final left vector            |
|   n[]  final right vector           |
|                                      |
|   Proof size: ~516 bytes (M=1, N=64) |
|   +64 bytes per M doubling          |
+--------------------------------------+
```

---

## API

Same interface as the other range proofs:

```cpp
auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPP::prove(
    amounts, blinding_factors);

bool valid = Crypto::RangeProofs::BulletproofsPP::verify(proof, commitments);
```

### Range parameter (`N`)

`prove` and `verify` accept an optional `N` (default 64) specifying the bit-length of
the range. `N` is silently rounded up to the nearest power of two with a minimum of 4
— allowed normalized values are `{4, 8, 16, 32, 64}`. This matches the
[`Bulletproofs`](../bulletproofs/README.md) (v1) silent-rounding convention so callers
can use the same idiom across all three Bulletproof variants. The same normalized `N`
must be used at both `prove` and `verify` time; the batch `verify` overload uses one
`N` for the entire batch.

`N` is bound into the Fiat-Shamir transcript on both sides, so a proof produced under
one normalized `N` will not validate under any other.

---

## Proof Sizes

| Values (M) | Proof Size | Prove Time | Verify Time |
|-----------|------------|------------|-------------|
| 1         | ~516 B     | ~3.7 ms    | ~470 us     |
| 2         | ~580 B     | ~7.5 ms    | ~540 us     |
| 4         | ~644 B     | ~15 ms     | ~640 us     |
| 8         | ~708 B     | ~30 ms     | ~760 us     |
| 16        | ~772 B     | ~60 ms     | ~900 us     |

---

## Comparison: Three Range Proof Generations

```
Proof size for M=1, N=64:

  Bulletproofs     ########################################  674 B
  Bulletproofs+    ################################        578 B
  Bulletproofs++   ##############################          516 B

All three prove the same thing: committed value is in [0, 2^64).
Each generation is smaller and faster than the last.
```

---

## Scenario: Aggregated Range Proof for a Transaction

```
FUNCTION aggregated_range_proof():
    // Alice's transaction has 2 outputs: 9 coins to Bob, 1 coin change.
    // She needs to prove BOTH amounts are non-negative, but she can
    // do it in a single compact proof instead of two separate ones.

    amounts   = [9, 1]
    blindings = [blinding_for_bob, blinding_for_change]

    // --- Prove -------------------------------------------------
    // The aggregated proof covers both values in ~580 bytes
    // (only 64 bytes more than a single-value proof!)

    [proof, commitments] = BulletproofsPP::prove(amounts, blindings)
    // proof.size() ~= 580 bytes
    // commitments = [C_bob, C_change]  (the Pedersen commitments)

    // --- Verify ------------------------------------------------
    // The verifier checks that ALL committed values are in [0, 2^64).
    // They learn nothing about the actual amounts (9 and 1).

    valid = BulletproofsPP::verify({proof}, {commitments})
    // valid == true

    // --- Batch verify (multiple transactions) -------------------
    // A block has 100 transactions, each with an aggregated proof.
    // Batch verification is much faster than verifying one at a time
    // because it combines all the multi-scalar multiplications.

    all_valid = BulletproofsPP::verify(
        [proof_tx1, proof_tx2, ..., proof_tx100],
        [commits_tx1, commits_tx2, ..., commits_tx100])
```

**Beyond financial transactions:** Range proofs work on any Pedersen commitment,
not just transaction amounts. Any application that uses commitments can also use
range proofs to prove the committed value is within a valid range. Examples:
proving an age is above 18 without revealing the exact age, proving a credit
score falls within an acceptable band, proving a sensor reading is within safe
operating limits in privacy-preserving IoT, or proving a vote index is valid
(between 0 and the number of candidates) in an anonymous voting system.

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 20-22 | Bulletproofs++ |

---

## Fuzz coverage

This module is exercised by the project-wide fuzz harness in
`src/fuzz/`. Two front-ends share the same per-target body so the
same harness code runs everywhere:

- **Portable smoke** (`crypto-fuzz-smoke`, every PR, every compiler):
  xoshiro256\*\*-driven PRNG harness with a configurable iteration
  budget via the `CRYPTO_FUZZ_SMOKE_ITERS` environment variable.
- **libFuzzer** (`crypto-fuzz-<target>`, nightly, Linux+Clang only):
  coverage-guided per-target binaries built with
  `-fsanitize=fuzzer,address,undefined`. The per-target time budget
  is configurable via `FUZZ_BUDGET_SECS` in
  `.github/workflows/fuzz-nightly.yml`.

Both front-ends classify the SAFE exception set
(`std::invalid_argument`, `std::out_of_range`, `std::length_error`,
`std::range_error`) as expected behavior; anything outside that set
is promoted to a fuzz finding.

### Target `bppp`

Source: [`src/fuzz/fuzz_target_bppp.cpp`](../../src/fuzz/fuzz_target_bppp.cpp)

Entry points exercised:

- `Crypto::RangeProofs::BulletproofsPP::prove`
- `Crypto::RangeProofs::BulletproofsPP::verify`
- `bulletproof_pp_t deserialization (binary + JSON)`

---

## References

| Topic | Link |
|-------|------|
| Bulletproofs++ | [Habock, 2022 (ePrint 2022/510)][bppp-paper] |
| Inner product arguments | [Bootle et al., 2016][ipa-paper] |
| Pedersen commitments | [Pedersen, 1991][pedersen-paper] |

[bppp-paper]: https://eprint.iacr.org/2022/510
[ipa-paper]: https://eprint.iacr.org/2016/263
[pedersen-paper]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9
