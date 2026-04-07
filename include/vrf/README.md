# VRF

A Verifiable Random Function (VRF) is a keyed hash with a proof of correctness.
Given a secret key and an input, it produces a pseudorandom output and a proof
that anyone can verify using only the public key.

**Namespace**: `Crypto::VRF` (native) and `Crypto::VRF::RFC9381`
**Header**: [`vrf.h`](vrf.h)
**Reference**: [RFC 9381 -- ECVRF-EDWARDS25519-SHA512-ELL2][rfc9381]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Magic dice analogy |
| [Two Variants](#two-variants) | Native vs RFC 9381 |
| [API](#api) | Prove and verify |
| [Scenario](#scenario-provably-fair-lottery) | Provably fair lottery |
| [Use Cases](#use-cases) | Randomness beacons, sortition, key transparency |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Specifications |

---

## How It Works (ELI5)

Think of a VRF as a **magic dice** that always lands on the same number for a
given input, but only the dice owner can roll it. Anyone can check that the roll
was fair (using the proof), but nobody else can predict or reproduce the number
without the secret key.

```
+-----------------------------------------------+
|                     VRF                       |
|                                               |
|  (secret_key, input) --> (output, proof)      |
|                                               |
|  Properties:                                  |
|   - Deterministic: same input -> same output  |
|   - Pseudorandom: output is indistinguishable |
|     from random without the secret key        |
|   - Verifiable: anyone with public_key can    |
|     check the proof                           |
|   - Unforgeable: can't produce valid proofs   |
|     without the secret key                    |
+-----------------------------------------------+
```

---

## Two Variants

| | Native | RFC 9381 |
|---|--------|----------|
| Hash-to-curve | Elligator + mul8 | SSWU (RFC 9380) |
| Challenge hash | SHA-3 | SHA-512 (truncated to 16 bytes) |
| Output hash | SHA-3 | SHA-512 |
| Proof size | 96 bytes | 80 bytes |
| Interoperable | Library-specific | Standards-compliant |

---

## API

```cpp
// Native variant
auto [proof, output] = Crypto::VRF::prove(secret_key, input_bytes);
auto [valid, output2] = Crypto::VRF::verify(public_key, input_bytes, proof);
// valid == true && output == output2

// RFC 9381 variant (interoperable) -- returns vrf_rfc9381_proof_t (80 B)
auto [rfc_proof, output] = Crypto::VRF::RFC9381::prove(secret_key, input_bytes);
auto [valid, output2] = Crypto::VRF::RFC9381::verify(public_key, input_bytes, rfc_proof);
```

---

## Scenario: Provably Fair Lottery

```
FUNCTION fair_lottery():
    // A lottery operator wants to draw a winner from 1000 tickets.
    // Players need to trust the draw is fair. A VRF lets the operator
    // prove the result is deterministic and correct.

    // The operator's key pair is published before ticket sales start.
    [operator_public, operator_secret] = Crypto::generate_keys()

    // After ticket sales close, the input is a public commitment:
    input = sha3("Lottery #42, block hash: abc123..., 1000 tickets")

    // The operator computes the VRF output:
    [proof, output] = VRF::prove(operator_secret, input)

    // The output is a 32-byte pseudorandom value.
    // Convert to a ticket number:
    winner = output_to_integer(output) % 1000    // e.g., ticket #739

    // Publish: (winner = 739, proof)
    // Anyone can verify:
    [valid, output2] = VRF::verify(operator_public, input, proof)
    assert(valid == true)
    assert(output_to_integer(output2) % 1000 == 739)

    // The proof guarantees:
    //   - The operator couldn't choose the winner (deterministic)
    //   - Nobody else could predict the winner (needs secret key)
    //   - Anyone can check the result is correct (verifiable)
```

---

## Use Cases

- **Provably fair randomness** -- lotteries, raffles, leader election in
  distributed protocols (e.g., selecting which node proposes the next block)
- **Randomness beacons** -- producing public, verifiable random values that
  no single party can bias
- **Sortition** -- randomly selecting a committee from a large group (e.g.,
  selecting validators for a consensus round), where each selected member
  can prove they were legitimately chosen
- **Key-transparent systems** -- proving a mapping from input to output is
  deterministic and honestly computed (e.g., CONIKS-style key transparency
  logs, DNSSEC)

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 27 | VRF |

---

## References

| Topic | Link |
|-------|------|
| VRF specification | [RFC 9381 -- ECVRF-EDWARDS25519-SHA512-ELL2][rfc9381] |

[rfc9381]: https://www.rfc-editor.org/rfc/rfc9381.html
