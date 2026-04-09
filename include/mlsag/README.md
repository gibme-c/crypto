# MLSAG

MLSAG (Multilayered Linkable Spontaneous Anonymous Group) is the predecessor to
CLSAG. It uses a two-column approach -- one column for the public key and one for
the commitment -- producing two response scalars per ring member instead of one.

**Namespace**: `Crypto::RingSignature::MLSAG`
**Header**: [`mlsag.h`](mlsag.h)
**Reference**: [Noether et al., 2015 (ePrint 2015/1098)][mlsag-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | The original ring signature, explained simply |
| [API](#api) | Ring signature generation and verification |
| [Signature Structure](#signature-structure) | Layout of the mlsag_signature_t |
| [CLSAG vs MLSAG](#clsag-vs-mlsag) | Size and feature comparison |
| [Mode Binding](#mode-binding) | How plain vs. commitment-binding mode is authenticated |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Imagine a **lineup of suspects**. You want to prove that one of them --
and you won't say which one -- signed a letter. A **ring signature** does
exactly that with math: you collect a bunch of public keys (yours plus
some decoys), and you produce a signature that only a real key-holder
could have made. The verifier sees "yes, one of these people signed it,"
but has no way to tell *which* one. Everyone in the lineup looks equally
guilty.

Every ring signature also publishes a **key image**: a unique one-way tag
derived from your secret key. It doesn't reveal who you are, but it's
always the same for the same secret. So if you try to spend the same coin
twice, the network sees the same tag twice and rejects the second
attempt -- no double-spending, no anonymity loss.

MLSAG -- *Multilayered* Linkable Spontaneous Anonymous Group -- was the
**original** ring signature used in Monero-style confidential transactions.
The "multilayered" part means it handles two columns at once: one for the
public keys (proving you own a key) and a second for the amount
commitments (proving your input amount matches a balancing commitment).
It was the workhorse for years.

The catch is that MLSAG produces **two response scalars per ring member**
instead of one, so the signature is roughly **twice as big** as it needs
to be. The newer **CLSAG** scheme proves the exact same thing with
identical security in half the space, so MLSAG has been superseded. It's
kept in the library mainly for **legacy and interoperability** with
systems that still use the old format -- for new designs you should
almost always reach for CLSAG instead.

---

## API

Same interface as [CLSAG](../clsag/README.md) (drop-in comparable). MLSAG uses the standard key
image formula `I = x * Hp(P)`, same as CLSAG and Borromean:

```cpp
auto [ok, sig] = Crypto::RingSignature::MLSAG::generate_ring_signature(
    digest, secret_key, ring_public_keys,
    input_blinding, ring_commitments,
    pseudo_blinding, pseudo_commitment);

// Key image (standard form, same as CLSAG/Borromean)
auto real_public_key = secret_key * Crypto::G;
auto key_image = Crypto::generate_key_image(real_public_key, secret_key);

bool valid = Crypto::RingSignature::MLSAG::check_ring_signature(
    digest, key_image, ring_public_keys, sig, ring_commitments);
```

---

## Signature Structure

```cpp
struct mlsag_signature_t {
    std::vector<scalar_t> key_scalars;         // N scalars (key column)
    std::vector<scalar_t> commitment_scalars;  // N scalars (commitment column)
    scalar_t challenge;                        // initial challenge
    key_image_t commitment_image;              // optional
    pedersen_commitment_t pseudo_commitment;   // optional
};
```

---

## CLSAG vs MLSAG

| | CLSAG | MLSAG |
|---|-------|-------|
| Scalars per ring member | 1 | 2 |
| Signature size (N=11) | ~416 B | ~768 B |
| Security | Equivalent | Equivalent |
| Status | Current | Legacy (superseded by CLSAG) |

**Prefer [CLSAG](../clsag/README.md)** for new designs -- it's half the size with identical security.

---

## Mode Binding

MLSAG runs in one of two modes per signature: **plain ring** (no commitment binding, `commitment_scalars` empty) or **commitment-binding ring** (with `commitment_image`, `pseudo_commitment`, and parallel `key_scalars` / `commitment_scalars` columns). Both directions of mode mismatch are rejected explicitly by two complementary mechanisms — identical in shape to the CLSAG design:

**Strict mode-mismatch reject** at the top of every `check_ring_signature` and `generate_ring_signature` entry point. The signer's mode is recovered from the signature's own fields (`commitment_image.valid() && pseudo_commitment.valid() && !commitment_scalars.empty()`); the caller's stated mode is recovered from the shape of the `commitments` vector (or, on the sign side, from whether all four commitment-mode arguments are validly populated). Disagreement in either direction is a hard `false` return.

**Transcript binding** of an explicit `uint8_t` mode tag (`0x00` plain, `0x01` commit) into the MLSAG challenge-chain transcript (`MLSAG_DOMAIN_0`). The tag is absorbed immediately after the domain separator, in both sign and verify, so `h0` itself becomes a function of the mode and the closing test `h[0] == h0` carries the mode authentication directly.

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 23-24 | MLSAG |

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

### Target `mlsag`

Source: [`src/fuzz/fuzz_target_mlsag.cpp`](../../src/fuzz/fuzz_target_mlsag.cpp)

Entry points exercised:

- `Crypto::RingSignature::MLSAG::generate_ring_signature (plain and commitment modes)`
- `Crypto::RingSignature::MLSAG::check_ring_signature (plain and commitment modes)`
- `mlsag_signature_t deserialization (binary + JSON)`

---

## References

| Topic | Link |
|-------|------|
| MLSAG / Ring Confidential Transactions | [Noether et al., 2015 (ePrint 2015/1098)][mlsag-paper] |

[mlsag-paper]: https://eprint.iacr.org/2015/1098
