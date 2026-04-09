# DLEQ Proofs

A Discrete Log Equality (DLEQ) proof demonstrates that two points share
the same discrete logarithm relative to different base points:

```
Given:  A = x * G   and   B = x * H
Prove:  DL_G(A) == DL_H(B)   (same x for both)
```

The proof is a single Schnorr-like sigma protocol producing two scalars
(64 bytes total: challenge `c` + response `s`). The verifier never learns `x`.

**Namespace**: `Crypto::DLEQ`
**Headers**: [`dleq.h`](dleq.h), [`dleq_proof_t.h`](dleq_proof_t.h)
**Algorithm**: Chaum-Pedersen protocol
**Domain constant**: `DLEQ_DOMAIN_0` (index 25)
**Reference**: [Chaum & Pedersen, 1992][chaum-pedersen]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Same-combination-lock analogy |
| [Protocol](#protocol) | Sigma protocol diagram |
| [API](#api) | Generate and verify proofs |
| [Proof Type](#proof-type) | `dleq_proof_t` structure |
| [Use Cases](#use-cases) | Key images, atomic swaps |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers |

---

## How It Works (ELI5)

Imagine you have a secret number (say, 7). You use it to open two
different combination locks -- one at the gym and one at the office. A DLEQ
proof lets you prove to someone that you used the *same secret number* for
both locks, without telling them what the number is. They can see both locks
are open, and the proof convinces them it was the same combination -- but
they still cannot figure out that the number is 7.

In the library, DLEQ proofs are used to tie related computations together.
For example, when constructing a key image `I = x * Hp(P)`, a DLEQ proof
shows that the same secret `x` was used for both the public key `P = x*G`
and the key image `I = x*Hp(P)` -- proving the key image is honestly
constructed without revealing `x`.

---

## Protocol

```
          Prover                          Verifier
            |                                |
   pick random k                             |
   R1 = k * G                                |
   R2 = k * H                                |
            |---- (R1, R2) --------->        |
            |                         c = H(G, H, A, B, R1, R2)
            |<--------- c ----------         |
   s = k + c * x                             |
            |---------- s ---------->        |
            |                         check: s*G == R1 + c*A ?
            |                         check: s*H == R2 + c*B ?
```

In practice the protocol is made non-interactive via Fiat-Shamir: the prover
computes `c` from the transcript instead of receiving it from the verifier.

---

## API

```cpp
// Prove: I know x such that A = x*G and B = x*H
auto proof = Crypto::DLEQ::generate_proof(x, G, H);

// Verify: A and B share the same discrete log
bool valid = Crypto::DLEQ::check_proof(A, B, G, H, proof);
```

---

## Proof Type

`dleq_proof_t` is a 64-byte structure containing:

| Field | Type | Description |
|-------|------|-------------|
| `c` | `scalar_t` | Fiat-Shamir challenge |
| `s` | `scalar_t` | Response scalar (`s = k + c * x`) |

Inherits from `Serializable` -- supports binary serialize/deserialize, JSON,
hex string conversion, and `operator<<` for debug output.

---

## Use Cases

- **Key image binding** -- proves `I = x*Hp(K)` was computed with the same `x`
  that produces `K = x*G`, tying a key image to its public key.
- **Atomic swaps** -- adaptor signatures use DLEQ to prove the same secret
  unlocks both sides of a cross-chain swap.

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 25 | DLEQ |

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

### Target `dleq`

Source: [`src/fuzz/fuzz_target_dleq.cpp`](../../src/fuzz/fuzz_target_dleq.cpp)

Entry points exercised:

- `Crypto::DLEQ::generate_proof`
- `Crypto::DLEQ::check_proof`
- `dleq_proof_t deserialization (binary + JSON)`

---

## References

| Topic | Link |
|-------|------|
| Chaum-Pedersen DLEQ | [Chaum & Pedersen, 1992: Wallet Databases with Observers][chaum-pedersen] |

[chaum-pedersen]: https://link.springer.com/chapter/10.1007/3-540-48071-4_7
