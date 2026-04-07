# RingCT

Ring Confidential Transactions provide the commitment layer that hides
transaction amounts. A Pedersen commitment `C = y*G + a*H` binds an amount `a`
with blinding factor `y` such that:

- Nobody can determine `a` from `C` (hiding)
- Nobody can find a different `(y', a')` that produces the same `C` (binding)
- Commitments are additively homomorphic: `C1 + C2 = (y1+y2)*G + (a1+a2)*H`

This last property is what makes confidential transactions work -- a verifier
can check that inputs and outputs balance without learning any amounts.

**Namespace**: `Crypto::RingCT`
**Header**: [`ringct.h`](ringct.h)
**Reference**: [Noether et al., 2015 (ePrint 2015/1098)][ringct-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Sealed envelopes and opaque commitments |
| [API](#api) | Pedersen commitments, pseudo commitments, parity checks |
| [Scenario](#scenario-alice-commits-to-42-coins) | Alice commits to 42 coins |
| [Use Cases](#use-cases) | Confidential transactions, amount encryption |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Imagine putting money in an opaque envelope (a "Pedersen commitment"):

```
  +---------------------------------+
  |          ENVELOPE #1            |
  |                                 |
  |   Contains: $42                 |   <-- only Alice knows this
  |   Sealed with: random wax #7a3f |   <-- only Alice knows this
  |                                 |
  |   What everyone sees:           |
  |   a3f2c9...b7 (32 opaque bytes) |   <-- the commitment
  +---------------------------------+

  Properties of this envelope:
    - You can't see inside it (hiding)
    - You can't swap what's inside after sealing (binding)
    - If you add two envelopes, the amounts inside add up:
        Envelope($42) + Envelope($8) = Envelope($50)
        (the math works even though nobody opened anything!)
```

```
+-------------------------------------------------+
|              Pedersen Commitment                 |
|                                                 |
|   C = y*G + a*H                                 |
|                                                 |
|   G = Ed25519 base point (known)                |
|   H = secondary generator    (known)            |
|   y = blinding factor        (secret)           |
|   a = amount                 (secret)           |
|                                                 |
|   Given C, nobody can recover (y, a).           |
|   Given C1, C2: C1 + C2 commits to (a1 + a2).  |
+-------------------------------------------------+
```

---

## API

```cpp
// Create a commitment to an amount: C = blinding*G + amount*H
// blinding: a random scalar that hides the amount (blinding_factor_t)
// amount:   the plaintext value to commit to (uint64_t)
auto C = Crypto::RingCT::generate_pedersen_commitment(blinding, amount);

// Generate pseudo-commitments for transaction inputs that balance against outputs.
// input_amounts:      the plaintext amounts of each input being spent
// output_blindings:   the blinding factors already chosen for the output commitments
// Returns: pseudo blinding factors and pseudo commitments for each input.
// The last input's blinding is computed so that sum(pseudo_blindings) == sum(output_blindings),
// ensuring the commitment sums cancel (amounts balance without revealing values).
auto [pseudo_blindings, pseudo_commitments] =
    Crypto::RingCT::generate_pseudo_commitments(input_amounts, output_blindings);

// Verify conservation: sum(pseudo_commitments) == sum(output_commitments) + fee*H
// This check passes if and only if the amounts balance: sum(inputs) == sum(outputs) + fee.
bool balanced = Crypto::RingCT::check_commitments_parity(
    pseudo_commitments, output_commitments, fee);

// Encrypt/decrypt amounts using XOR with a derived mask.
// amount_mask: derived from the shared ECDH secret (so only the recipient can decrypt)
// amount_scalar: the amount encoded as a scalar
// The same function both encrypts and decrypts (XOR is its own inverse).
auto masked = Crypto::RingCT::toggle_masked_amount(amount_mask, amount_scalar);
auto recovered = Crypto::RingCT::toggle_masked_amount(amount_mask, masked);
// recovered == amount_scalar
```

---

## Scenario: Alice Commits to 42 Coins

```
FUNCTION demonstrate_commitments():
    // Alice puts 42 coins in an opaque envelope (commitment).
    // She also puts 8 coins in another envelope.
    // She then proves the envelopes add up to 50, without opening either one.

    // --- Create commitments ----------------------------------------
    blinding_1 = random_scalar()
    C1 = blinding_1 * G + 42 * H       // hides 42 coins

    blinding_2 = random_scalar()
    C2 = blinding_2 * G + 8 * H        // hides 8 coins

    // --- Homomorphic addition ----------------------------------------
    // C1 + C2 = (blinding_1 + blinding_2) * G + (42 + 8) * H
    //         = (blinding_1 + blinding_2) * G + 50 * H
    // The sum commits to 50 -- without opening either envelope!

    C_sum = C1 + C2

    // --- Balance check -----------------------------------------------
    // If Alice creates an output commitment for 50 coins:
    blinding_out = blinding_1 + blinding_2    // must match!
    C_out = blinding_out * G + 50 * H

    // Then C_sum - C_out = 0 (the identity point).
    // The verifier checks this equality WITHOUT knowing any amounts.
    // If Alice tried to claim the outputs total 51, the check fails.
```

---

## Use Cases

- **Confidential transactions** -- hiding transfer amounts while proving
  that inputs and outputs balance (no coins created or destroyed)
- **Amount encryption** -- masking the committed value with a shared secret
  so only the intended recipient can decrypt it
- **Foundation for range proofs** -- the commitment is what range proofs
  operate on (proving the committed value is non-negative)

**Beyond financial transactions:** Pedersen commitments work anywhere you
need to commit to a value without revealing it, then later prove properties
about that value. Examples include sealed-bid auctions (commit to your bid,
reveal later), commit-reveal voting schemes, verifiable shuffles in mixnets,
and confidential asset registries where ownership quantities must be hidden.

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 8-9 | RingCT masks |

---

## References

| Topic | Link |
|-------|------|
| Ring Confidential Transactions | [Noether et al., 2015 (ePrint 2015/1098)][ringct-paper] |
| Pedersen commitments | [Pedersen, 1991][pedersen-paper] |

[ringct-paper]: https://eprint.iacr.org/2015/1098
[pedersen-paper]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9
