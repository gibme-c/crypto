# Bulletproofs+

An improved range proof variant that replaces the standard inner product argument
with a weighted inner product argument (WIPA). The result is a smaller proof and
faster verification with the same security guarantees: each committed value lies
in `[0, 2^N)`.

The API mirrors the original [Bulletproofs](../bulletproofs/README.md) interface
-- it is a drop-in replacement with better size and performance characteristics.

**Namespace**: `Crypto::RangeProofs::BulletproofsPlus`
**Header**: [`bulletproofsplus.h`](bulletproofsplus.h)
**Reference**: [Chung et al., 2020 (ePrint 2020/735)][bpplus-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Weighted inner product argument |
| [API](#api) | Prove, verify, and batch-verify |
| [Range Parameter](#range-parameter) | Silent rounding and Fiat-Shamir binding of N |
| [Proof Sizes](#proof-sizes) | Size by aggregation count |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Like original [Bulletproofs](../bulletproofs/README.md), Bulletproofs+ prove that
a committed value is non-negative without revealing it. The key innovation is the
**weighted inner product argument** (WIPA), which replaces the standard IPA. The
weighting lets the prover fold the proof more efficiently, shaving about 96 bytes
off every proof and improving verification speed. The security guarantees are
identical.

---

## API

Same interface as Bulletproofs -- drop-in replacement:

```cpp
auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove(
    amounts, blinding_factors);

bool valid = Crypto::RangeProofs::BulletproofsPlus::verify(proof, commitments);
```

---

## Range Parameter

Identical contract to original Bulletproofs — see
[the BP "Range Parameter" section](../bulletproofs/README.md#range-parameter)
for the silent `pow2_round` rule, the Fiat-Shamir binding of `N`, and why this
is hygiene / availability rather than a soundness concern.

---

## Proof Sizes

| Values (M) | Proof Size |
|-----------|------------|
| 1         | ~578 B     |
| 2         | ~642 B     |
| 4         | ~706 B     |
| 8         | ~770 B     |
| 16        | ~834 B     |

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 15-17 | Bulletproofs+ |

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

### Target `bpplus`

Source: [`src/fuzz/fuzz_target_bpplus.cpp`](../../src/fuzz/fuzz_target_bpplus.cpp)

Entry points exercised:

- `Crypto::RangeProofs::BulletproofsPlus::prove`
- `Crypto::RangeProofs::BulletproofsPlus::verify`
- `bulletproof_plus_t deserialization (binary + JSON)`

---

## References

| Topic | Link |
|-------|------|
| Bulletproofs+ | [Chung et al., 2020 (ePrint 2020/735)][bpplus-paper] |
| Inner product arguments | [Bootle et al., 2016][ipa-paper] |
| Pedersen commitments | [Pedersen, 1991][pedersen-paper] |

[bpplus-paper]: https://eprint.iacr.org/2020/735
[ipa-paper]: https://eprint.iacr.org/2016/263
[pedersen-paper]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9
