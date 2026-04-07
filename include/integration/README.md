# Integration Module

This directory contains higher-level protocols that build on the core
cryptographic primitives to solve real-world integration problems. Rather
than raw signatures or proofs, these are **application-facing tools** --
things you hand to an auditor, a regulator, or an automated compliance
system.

All headers are accessible through `#include <crypto.h>`.

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Integration tools in plain English |
| [Audit Proofs](#audit-proofs) | Prove ownership of outputs without revealing secrets |
| [Scenario: Exchange Proof-of-Reserves](#scenario-exchange-proof-of-reserves) | Worked example |
| [Use Cases](#use-cases) | When and why you would use audit proofs |

---

## How It Works (ELI5)

Imagine you run a bank and a government auditor walks in. The auditor wants
to know: "Do you actually have the money you claim to have?" In a normal
bank you open the vault and let them count the gold bars. But in a
privacy-preserving system, opening the vault would reveal your
secret keys -- and anyone who sees those keys could steal everything.

Audit proofs solve this problem. They let you **prove you hold the keys to
specific outputs** (coins) without ever exposing the keys themselves. It is
like showing the auditor a signed photograph of you standing next to each
gold bar, with today's newspaper in frame, without ever giving them the
combination to the vault.

```
  THE AUDIT PROOF FLOW
  ────────────────────

  Exchange (prover)                    Auditor (verifier)
       |                                     |
       |  "I control these 5 outputs"        |
       |                                     |
       |  secret_keys ──> generate_proof     |
       |                      |              |
       |              proof_string           |
       |        (Base58-encoded, safe        |
       |         to transmit publicly)       |
       |                      |              |
       |  ---- proof_string --------->       |
       |                                     |
       |                       public_keys + |
       |                       proof_string  |
       |                           |         |
       |                     check_proof     |
       |                           |         |
       |                   valid? + key_images
       |                                     |
       |                   "Yes, they own    |
       |                    all 5 outputs    |
       |                    and none are     |
       |                    double-spent."   |
```

The key images returned by verification serve a second purpose: the auditor
can cross-reference them against the ledger's spent-set to confirm that
the proven outputs have not already been spent.

---

## Audit Proofs

**Namespace**: `Crypto::Audit`
**Header**: [`audit.h`](audit.h)
**Domain constant**: `OUTPUT_PROOF_DOMAIN` (index 18)

Ownership proofs let a key holder demonstrate control of a set of outputs
without revealing the secret keys themselves. The proof is packaged as a
Base58-encoded string for easy transmission.

### API

The `secret_keys` are the one-time secret ephemeral keys (`p` values) that
correspond to specific outputs. These come from the stealth address derivation
process (see `core/crypto_common.h` -- Key Derivation). Each output on the
network has a one-time public key (`P`); the owner of that output knows the
corresponding secret key `p` (derived from `Ds + spend_secret`). These are
the keys you pass to the proof generator.

```cpp
// secret_keys: the one-time secret ephemeral scalars for outputs you control.
// Each scalar corresponds to one output on the ledger (from stealth address derivation).
auto [ok, proof_string] = Crypto::Audit::generate_outputs_proof(secret_keys);
// ok == true: proof successfully generated
// proof_string: Base58-encoded, safe to transmit over any channel

// public_keys: the one-time public keys for the same outputs (from the ledger).
// The auditor reads these from the public ledger -- no secrets needed.
auto [valid, key_images] = Crypto::Audit::check_outputs_proof(
    public_keys, proof_string);
// valid == true: the prover controls all listed outputs
// key_images: one per output, cross-reference against the spent-set
//             to confirm the outputs haven't already been spent
```

**Parameters**:

| Function | Input | Output |
|----------|-------|--------|
| `generate_outputs_proof` | `vector<scalar_t>` secret ephemeral keys (one per output) | `(bool success, string proof)` |
| `check_outputs_proof` | `vector<public_key_t>` public keys (same outputs, from the ledger), `string` proof | `(bool valid, vector<key_image_t>)` |

The proof string is self-contained -- it encodes the key images and
signatures for every output. The verifier only needs the public keys
(which are already visible on the ledger) and the proof string.

---

## Scenario: Exchange Proof-of-Reserves

```
FUNCTION proof_of_reserves():
    // An exchange wants to prove it controls the funds
    // it claims to hold, without revealing its secret keys.

    // The exchange has 5 outputs (coins) it controls:
    outputs = [output_1, output_2, output_3, output_4, output_5]
    secret_keys = [sk_1, sk_2, sk_3, sk_4, sk_5]

    // Generate a proof of ownership:
    [ok, proof_string] = Audit::generate_outputs_proof(secret_keys)
    // proof_string is a Base58-encoded string

    // An independent auditor verifies:
    public_keys = [pk_1, pk_2, pk_3, pk_4, pk_5]
    [valid, key_images] = Audit::check_outputs_proof(public_keys, proof_string)
    // valid == true -- the exchange controls all 5 outputs

    // The auditor also checks that none of the key images appear
    // in the spent-set (the coins haven't already been spent).
```

### Step-by-Step Walkthrough

1. **Collect outputs.** The exchange gathers the secret ephemeral keys for
   every unspent output it claims to control.

2. **Generate proof.** `generate_outputs_proof` signs each output with its
   secret key and packs the signatures and key images into a single
   Base58-encoded string.

3. **Transmit proof.** The exchange sends the proof string to the auditor.
   The string contains no secret material -- it is safe to transmit over
   any channel.

4. **Verify proof.** The auditor calls `check_outputs_proof` with the
   public keys (read from the public ledger) and the proof string. If all
   signatures check out, the function returns `true` along with the key
   images.

5. **Check spent-set.** The auditor compares the returned key images against
   the ledger's record of spent key images. Any match means that output
   has already been spent and should not count toward reserves.

---

## Use Cases

- **Exchange proof-of-reserves** -- prove you control outputs without moving
  them, allowing third-party auditors to verify solvency.
- **Selective disclosure for regulatory compliance** -- show a regulator that
  you hold specific funds without revealing your full wallet or transaction
  history.
- **Third-party auditing** -- an independent auditor can verify holdings at
  any point in time without the exchange surrendering custody of its keys.
- **Dispute resolution** -- prove to a counterparty that you controlled
  certain outputs at a specific time, useful for contractual or legal
  proceedings.
