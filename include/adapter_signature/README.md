# Adapter Signatures

An adapter signature is a pre-signature that is locked to a statement point
`Y = y*G`. The pre-signature can be verified to be correct, but is not a valid
signature until the witness scalar `y` is revealed. Once adapted (by adding `y`
to the response), anyone who saw both the pre-signature and the final signature
can extract the witness.

This creates a trustless atomic swap mechanism: Alice locks her pre-signature to
Bob's statement, and when Bob reveals `y` to complete the swap on one chain,
Alice can extract `y` from the completed signature and claim her side.

**Namespace**: `Crypto::AdapterSignature`
**Header**: [`adapter_signature.h`](adapter_signature.h)
**Reference**: [Chaum & Pedersen, 1992][chaum-pedersen]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Pre-signatures and atomic swaps in plain English |
| [How It Works](#how-it-works) | Adapter signature flow diagram |
| [API](#api) | Pre-sign, check, adapt, extract |
| [Scenario](#scenario-cross-chain-atomic-swap) | Cross-chain atomic swap walkthrough |
| [Pre-Signature Structure](#pre-signature-structure) | Layout of the adapter_signature_t |
| [Use Cases](#use-cases) | Atomic swaps, payment channels, fair exchange |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

A normal **signature** is final. You sign a message, you hand over the
signature, and anyone in the world can verify it. Once it's out there,
it's done -- there's no "almost signed" state.

An **adapter signature** (also called a pre-signature) is a clever twist:
it's a signature that's been **locked behind a secret**. It looks almost
like a real signature, and anyone can verify that it's been *correctly
constructed* -- but it is **not yet valid**. Think of it like a key that's
been cut to the right shape but has one notch missing. You can tell by
looking at it that it's going to fit a particular lock, but in its current
state it won't actually turn.

The missing notch is a secret scalar called the **witness**. Whoever
knows the witness can "adapt" the pre-signature -- fill in the missing
notch -- and turn it into a fully valid signature. Here's the magical
part: once the completed signature gets published (for example, to claim
coins on a blockchain), **anyone who also saw the original pre-signature
can subtract one from the other and recover the witness**. Publishing the
valid signature inevitably leaks the secret.

This is what makes **trustless atomic swaps** work. Suppose Alice has
coins on Chain A and Bob has coins on Chain B, and they want to trade
without trusting each other:

```
  1. Bob picks a secret y and publishes Y = y*G  ("the lock")
  2. Alice pre-signs a Chain A payment to Bob, locked to Y
     Bob can see the pre-sig is valid-once-y-is-revealed
  3. Bob adds y to the pre-sig, broadcasts on Chain A, gets paid
     But doing so puts the completed signature on the public ledger
  4. Alice watches Chain A, subtracts pre-sig from the completed sig,
     recovers y, and uses it to claim Bob's coins on Chain B
```

Neither party can cheat. If Bob never claims, Alice's coins just stay
locked (a timeout lets her recover them). If Bob *does* claim, he has no
choice but to reveal the secret that lets Alice claim her side. The math
enforces fairness so no trusted middleman is needed.

---

## How It Works

```
+----------------------------------------------------------------+
|                    Adapter Signature Flow                       |
|                                                                |
|   Setup:                                                       |
|     Bob publishes statement Y = y*G  (keeps y secret)          |
|                                                                |
|   Step 1 -- Pre-sign:                                          |
|     Alice creates pre-signature s' locked to Y                 |
|     s' is NOT a valid signature, but verifiably correct        |
|                                                                |
|   Step 2 -- Adapt:                                             |
|     Bob adds witness y to get valid signature s = s' + y       |
|     Bob publishes s (e.g., to claim coins on chain A)          |
|                                                                |
|   Step 3 -- Extract:                                           |
|     Alice sees s' and s, computes y = s - s'                   |
|     Alice uses y to claim coins on chain B                     |
|                                                                |
|   Result: trustless atomic exchange of y for a valid signature |
+----------------------------------------------------------------+
```

---

## API

```cpp
// Step 1: Alice pre-signs, locked to Bob's statement Y
auto pre_sig = Crypto::AdapterSignature::pre_sign(digest, alice_secret, Y);

// Verify the pre-signature is correctly formed (anyone can check)
bool correct = Crypto::AdapterSignature::check_pre_signature(
    digest, alice_public, Y, pre_sig);

// Step 2: Bob adapts with witness y to produce a Schnorr (R', s) signature
//         under the adapter Fiat-Shamir domain. NOTE: this is NOT a standard
//         Ed25519 signature — it uses a distinct domain tag and must be
//         verified with check_adapted_signature, not Crypto::Signature::check_signature.
auto adapted = Crypto::AdapterSignature::adapt(pre_sig, y);

// Verify the adapted signature under the adapter domain
bool valid = Crypto::AdapterSignature::check_adapted_signature(digest, alice_public, adapted);

// Step 3: Alice extracts the witness from the difference
auto y_extracted = Crypto::AdapterSignature::extract(pre_sig, adapted, Y);
// y_extracted == y
```

---

## Scenario: Cross-Chain Atomic Swap

```
FUNCTION atomic_swap():
    // Alice has 1 BTC-like coin on Chain A.
    // Bob has 100 XMR-like coins on Chain B.
    // They want to swap trustlessly -- neither can cheat.

    // --- Setup: Bob creates the secret ------------------------------
    // Bob picks a random witness y and publishes Y = y * G.
    // This is the "lock" that ties both chains together.

    y = random_scalar()
    Y = y * G           // Bob publishes Y, keeps y secret

    // --- Step 1: Alice locks her coin with an adapter sig -----------
    // Alice creates a pre-signature on Chain A that sends her coin
    // to Bob, but the pre-signature isn't valid without y.

    tx_a = "Send 1 coin from Alice to Bob on Chain A"
    digest_a = sha3(tx_a)

    pre_sig = AdapterSignature::pre_sign(digest_a, alice_secret, Y)

    // Bob verifies the pre-signature is correct:
    ok = AdapterSignature::check_pre_signature(
        digest_a, alice_public, Y, pre_sig)
    // ok == true -- Bob knows: "If I reveal y, this becomes a valid
    // signature that sends me Alice's coin."

    // --- Step 2: Bob claims on Chain A (reveals y) ------------------
    // Bob adds his witness y to Alice's pre-signature to produce a
    // Schnorr (R', s) signature under the adapter Fiat-Shamir domain,
    // then broadcasts it on Chain A. Note: the adapted signature is
    // NOT a standard Ed25519 signature -- it uses a distinct domain tag
    // and is verified by AdapterSignature::check_adapted_signature. Chain A
    // must support the adapter-domain verification rule (e.g. as a script
    // or protocol-native opcode) for this to settle on-chain.

    sig_a = AdapterSignature::adapt(pre_sig, y)
    // sig_a is the (R', s) adapted signature -- Bob submits it and
    // receives Alice's coin.

    // But by doing this, Bob published sig_a on the public ledger!

    // --- Step 3: Alice extracts y and claims on Chain B -------------
    // Alice sees both pre_sig (she created it) and sig_a (Bob
    // published it). The difference reveals y.

    y_extracted = AdapterSignature::extract(pre_sig, sig_a, Y)
    // y_extracted == y  (Alice now knows Bob's secret!)

    // Alice uses y_extracted to claim Bob's coins on Chain B.

    // --- Result -----------------------------------------------------
    // Alice: gave up 1 BTC-like coin, got 100 XMR-like coins
    // Bob:   gave up 100 XMR-like coins, got 1 BTC-like coin
    // Nobody trusted anyone -- the math guaranteed fairness.
    //
    // If Bob never reveals y (doesn't claim), Alice's coin
    // stays locked forever -- but Bob can't claim it either.
    // In practice, a timelock lets Alice reclaim after a deadline.
```

---

## Pre-Signature Structure

```cpp
struct adapter_signature_t {
    point_t adapted_nonce;   // R' = R + Y (32 bytes)
    scalar_t s_prime;        // pre-response scalar (32 bytes)
    dleq_proof_t dleq;      // proof of correct construction (64 bytes)
};
// Total: 128 bytes
```

The DLEQ proof guarantees the pre-signature was honestly constructed -- without
it, Alice could create a pre-signature that adapts to a valid signature but
doesn't allow witness extraction.

---

## Use Cases

- **Cross-chain atomic swaps** -- exchange assets between two independent
  systems without a trusted intermediary and without hash time locks (which
  leak timing metadata)
- **Payment channel updates** -- conditional signatures that only become
  valid when a counterparty reveals a secret, enabling off-chain state
  transitions
- **Fair exchange protocols** -- trade a secret for a signature atomically;
  neither party can cheat because the secret is cryptographically bound to
  the signature
- **Contingent payments** -- pay for data delivery where the payment
  automatically completes when the data (the witness scalar) is revealed
- **Beyond financial applications** -- any protocol that needs "if you
  reveal secret X, then signature Y becomes valid" -- for example, key
  escrow release, conditional access grants, or verifiable encryption

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 25 | DLEQ (used by adapter signatures) |
| 26 | Adapter signatures |

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

### Target `adapter`

Source: [`src/fuzz/fuzz_target_adapter.cpp`](../../src/fuzz/fuzz_target_adapter.cpp)

Entry points exercised:

- `Crypto::AdapterSignature::generate_adapter_signature`
- `Crypto::AdapterSignature::check_adapter_signature`
- `Crypto::AdapterSignature::adapt and recover paths`
- `adapter_signature_t / adapted_signature_t deserialization`

---

## References

| Topic | Link |
|-------|------|
| Chaum-Pedersen DLEQ proofs | [Chaum & Pedersen, 1992][chaum-pedersen] |

[chaum-pedersen]: https://link.springer.com/chapter/10.1007/3-540-48071-4_7
