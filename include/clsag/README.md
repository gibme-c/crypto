# CLSAG

CLSAG (Concise Linkable Spontaneous Anonymous Group) is a compact ring
signature that halves the size of MLSAG while maintaining the same security
properties. It optionally binds to Pedersen commitments for use in confidential
transactions.

**Namespace**: `Crypto::RingSignature::CLSAG`
**Header**: [`clsag.h`](clsag.h)
**Reference**: [Goodell et al., 2019 (ePrint 2019/654)][clsag-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Ring signatures and commitment binding in plain English |
| [API](#api) | Ring signature generation and verification |
| [Use Cases](#use-cases) | Privacy-preserving transactions |
| [Ring Signature Comparison](#ring-signature-comparison) | Side-by-side comparison of all ring sig schemes |
| [Transaction Signing](#transaction-signing-with-ring-signatures) | Full Alice/Bob walkthrough with CLSAG + BP++ |
| [Mode Binding](#mode-binding) | How plain vs. commitment-binding mode is authenticated |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Imagine a **group photo** of eleven people. You want to prove to someone
that *you are one of the people in this photo* without pointing yourself
out. A **ring signature** is the math version of that: you collect a bunch
of public keys (yours plus some decoys), and you produce a signature that
only a real key-holder could have made -- but the verifier has no way to
tell *which* of the eleven you are. From the outside, every face in the
photo is equally likely.

Every ring signature also publishes a **key image**, a unique tag derived
from your secret key in a one-way way. It doesn't reveal who you are, but
it's always the same for the same secret. So if someone tries to sign with
the same coin twice, the network sees the same tag show up twice and
rejects the second one. That's how you stop double-spending without
breaking anonymity.

CLSAG is the **modern compact variant**. It does exactly what the older
MLSAG scheme did, but the signature is **half the size** with the same
security. That's a big deal on a blockchain where every byte is stored
forever. CLSAG can also optionally **bind to Pedersen commitments**: in
one combined proof it says "I own one of these keys *and* the amount in
my input matches my balancing commitment." That single binding is what
lets confidential transactions hide both *who* spent and *how much* was
spent, all in one compact signature.

Compared to its siblings: Borromean is the simple older cousin (linear
size, no commitment binding), MLSAG is the ancestor CLSAG replaced
(same security, twice the size), and Triptych is the next-generation
variant where signature size grows *logarithmically* with ring size --
perfect when you want huge anonymity sets. For typical transactions with
small-to-medium rings, CLSAG is usually the right choice.

---

```
+----------------------------------------------------------+
|                    CLSAG Signature                       |
|                                                          |
|   Ring members:  {(K0,C0), (K1,C1), ..., (K_{n-1},...)} |
|                                                          |
|   Proves:                                                |
|     1. Knowledge of x: K_real = x*G                      |
|     2. Knowledge of z: C_real - C_pseudo = z*G           |
|        (i.e., input and pseudo commitment hide same d)   |
|                                                          |
|   Components:                                            |
|     challenge c1         (32 bytes)                      |
|     scalars s0..s_{n-1}  (32 bytes each)                 |
|     commitment_image D   (32 bytes, optional)            |
|     pseudo_commitment    (32 bytes, optional)            |
|                                                          |
|   Signature size: 32 + 32N bytes (+ 64 with commitments) |
+----------------------------------------------------------+
```

---

## API

```cpp
// Simple ring signature (no commitment binding).
// digest:           the transaction hash (binds the signature to this tx)
// secret_key:       the one-time secret key for the real output being spent
//                   (from stealth address derivation: p = Ds + spend_secret)
// ring_public_keys: all public keys in the ring (real signer + decoys).
//                   The function auto-detects which key matches secret_key.
auto [ok, sig] = Crypto::RingSignature::CLSAG::generate_ring_signature(
    digest, secret_key, ring_public_keys);

// With Pedersen commitment binding (confidential transactions).
// This additionally proves the signer knows the blinding factor difference
// between the real input commitment and the pseudo-commitment.
auto [ok, sig] = Crypto::RingSignature::CLSAG::generate_ring_signature(
    digest, secret_key, ring_public_keys,
    input_blinding,        // blinding factor of the real input's commitment
    ring_commitments,      // Pedersen commitments for all ring members (real + decoys)
    pseudo_blinding,       // blinding factor chosen for the pseudo-commitment
    pseudo_commitment);    // reblinded commitment (for balance checking)

// Compute the key image (published alongside the signature for double-spend detection).
// The key image is NOT part of the signature struct -- it must be computed separately.
auto real_public_key = secret_key * Crypto::G;
auto key_image = Crypto::generate_key_image(real_public_key, secret_key);

// Verify (with or without commitments).
// ring_commitments: pass {} if no commitment binding was used.
bool valid = Crypto::RingSignature::CLSAG::check_ring_signature(
    digest, key_image, ring_public_keys, sig, ring_commitments);
```

---

## Use Cases

- **Privacy-preserving transaction inputs** -- hides which output is being spent
  among a ring of decoys, while the key image prevents double-spending
- **Confidential transaction integration** -- commitment binding proves the signer
  knows the blinding factor difference, linking the ring signature to the
  transaction's balance proof without revealing any amounts
- **Anonymous group authentication** -- prove membership in a set of authorized
  keys without revealing which key was used (e.g., anonymous access control,
  whistleblower systems)

---

## Ring Signature Comparison

All four ring signature schemes prove the same fundamental statement -- "I know
one secret key in this ring" -- but with different trade-offs:

```
Signature size vs ring size N:

  Borromean  ################################################   64N B
  MLSAG      ##################################                 32 + 64N B
  CLSAG      #####################                               32 + 32N B
  Triptych   ##########                                         352 + 64*log2(N) B

  (shown for N=16)
```

### Size Comparison Table

| Ring Size | Borromean | MLSAG | CLSAG | Triptych |
|-----------|----------|-------|-------|----------|
| N=4 | 256 B | 288 B | 160 B | 480 B |
| N=8 | 512 B | 544 B | 288 B | 544 B |
| N=16 | 1,024 B | 1,056 B | 544 B | 608 B |
| N=64 | 4,096 B | 4,128 B | 2,080 B | 736 B |
| N=256 | 16,384 B | 16,416 B | 8,224 B | 864 B |
| N=1024 | 65,536 B | 65,568 B | 32,800 B | 992 B |

### Feature Comparison

| Feature | Borromean | MLSAG | CLSAG | Triptych |
|---------|-----------|-------|-------|----------|
| Linkable (key image) | Yes | Yes | Yes | Yes |
| Commitment binding | No | Optional | Optional | Required |
| Ring size constraint | Any | Any | Any | Power of 2 |
| Size scaling | O(N) | O(N) | O(N) | O(log N) |
| Split signing | No | No | No | Yes |
| Status | Legacy | Legacy | Current | Next-gen |

### Which One Should I Use?

- **Small rings (N < 32)**: Use **CLSAG** -- smallest size, well-proven, optional
  commitment binding
- **Large rings (N >= 64)**: Use **[Triptych](../triptych/README.md)** -- logarithmic scaling wins
  decisively, but requires power-of-2 ring size and requires commitment binding
- **Legacy compatibility**: Use **[MLSAG](../mlsag/README.md)** only if you need to interoperate
  with systems that already use MLSAG. For all new designs, prefer CLSAG.

**Beyond financial transactions:** Ring signatures are useful anywhere you
need to prove group membership without revealing your identity within the
group. Examples include anonymous whistleblower authentication (prove you are
one of the employees without revealing which one), anonymous voting (prove
eligibility without revealing your vote), and private access control (prove
you hold one of the authorized keys without revealing which).

---

## Transaction Signing with Ring Signatures

Here is how ring signatures fit into a traditional privacy-preserving
transaction. This shows CLSAG with BP++ range proofs.

**Scenario**: Alice wants to send 9 coins to Bob and keep 1 coin as change.
She has 2 unspent outputs (7 coins and 3 coins) that she'll spend as inputs.
Each input is hidden among 10 decoy public keys (ring size 11).

```
Alice's wallet knows (secret):          The network knows (public):
  - her secret keys (x1, x2)            - the ledger (all past outputs)
  - which outputs are hers               - previously-seen key images
  - the amounts (7 coins, 3 coins)       - nothing else!
  - Bob's address
```

### Signing (Sender)

```
FUNCTION build_transaction():
    // Alice is spending 7 + 3 = 10 coins total.
    // She sends 9 to Bob and 1 back to herself as change.
    // Fee is 0 for simplicity.

    // --- Step 1: Create new outputs (coins) ----------------------------
    // Each output hides its amount inside a "Pedersen commitment."
    // Think of it like putting money in an opaque envelope -- you can't
    // see how much is inside, but the math guarantees the totals add up.

    // Output #1: 9 coins to Bob
    blinding_1 = random_scalar()                       // random "seal" for the envelope
    commitment_1 = blinding_1 * G + 9 * H              // the sealed envelope
    one_time_key_1 = derive_stealth_address(bob)       // address only Bob can find
    encrypted_amount_1 = encrypt(9, shared_secret_1)   // amount encrypted to Bob

    // Output #2: 1 coin back to Alice (change)
    blinding_2 = random_scalar()
    commitment_2 = blinding_2 * G + 1 * H
    one_time_key_2 = derive_stealth_address(alice)
    encrypted_amount_2 = encrypt(1, shared_secret_2)

    // Range proof: one compact proof that BOTH output amounts
    // are in [0, 2^64). Prevents Alice from creating negative amounts.
    range_proof = BulletproofsPP::prove(
        amounts:   [9, 1],
        blindings: [blinding_1, blinding_2])

    // --- Step 2: Balance input commitments against outputs -------------
    // Choose pseudo-blindings so they sum to the output blindings.
    // This lets the network verify amounts balance without seeing them.
    //
    // The trick: (pseudo_blinding_1 + pseudo_blinding_2)
    //         == (blinding_1 + blinding_2)
    //
    // Then the Pedersen commitments cancel out:
    //   (pseudo_1 + pseudo_2) - (commitment_1 + commitment_2) - fee*H
    //   = (sum_blindings)*G + (7+3)*H - (sum_blindings)*G - (9+1)*H - 0*H
    //   = 0   (amounts balance!)

    pseudo_blinding_1 = random_scalar()
    pseudo_blinding_2 = (blinding_1 + blinding_2) - pseudo_blinding_1

    pseudo_commitment_1 = pseudo_blinding_1 * G + 7 * H   // hides "7 coins"
    pseudo_commitment_2 = pseudo_blinding_2 * G + 3 * H   // hides "3 coins"

    // --- Step 3: Ring signatures (one per input) -----------------------
    // Each input picks 10 decoy public keys from the ledger.
    // The CLSAG proves Alice owns ONE of the 11 keys without
    // revealing which one.

    tx_prefix_hash = hash(
        one_time_key_1, commitment_1, encrypted_amount_1,
        one_time_key_2, commitment_2, encrypted_amount_2,
        fee)

    // Input #1: Alice's 7-coin output (she's key #4 in the ring)
    ring_keys_1 = [
        decoy_key_0, decoy_key_1, decoy_key_2, decoy_key_3,
        alice_public_1,                    // <-- real signer at index 4
        decoy_key_5, decoy_key_6, decoy_key_7,
        decoy_key_8, decoy_key_9, decoy_key_10
    ]
    ring_commitments_1 = [
        decoy_comm_0, decoy_comm_1, decoy_comm_2, decoy_comm_3,
        alice_original_commitment_1,       // <-- real commitment at index 4
        decoy_comm_5, decoy_comm_6, decoy_comm_7,
        decoy_comm_8, decoy_comm_9, decoy_comm_10
    ]

    sig_1, key_image_1 = CLSAG::generate_ring_signature(
        tx_prefix_hash,
        alice_secret_1,           // Alice's secret key for this output
        ring_keys_1,              // 11 public keys (real + 10 decoys)
        alice_blinding_1,         // blinding factor of real input commitment
        ring_commitments_1,       // 11 Pedersen commitments (real + 10 decoys)
        pseudo_blinding_1,        // blinding factor for pseudo-commitment
        pseudo_commitment_1)      // reblinded commitment for balance check

    // Input #2: Alice's 3-coin output (she's key #9 in the ring)
    ring_keys_2 = [
        decoy_key_0, decoy_key_1, decoy_key_2, decoy_key_3,
        decoy_key_4, decoy_key_5, decoy_key_6, decoy_key_7,
        decoy_key_8,
        alice_public_2,                    // <-- real signer at index 9
        decoy_key_10
    ]
    ring_commitments_2 = [
        decoy_comm_0, decoy_comm_1, decoy_comm_2, decoy_comm_3,
        decoy_comm_4, decoy_comm_5, decoy_comm_6, decoy_comm_7,
        decoy_comm_8,
        alice_original_commitment_2,       // <-- real commitment at index 9
        decoy_comm_10
    ]

    sig_2, key_image_2 = CLSAG::generate_ring_signature(
        tx_prefix_hash,
        alice_secret_2,
        ring_keys_2,
        alice_blinding_2,
        ring_commitments_2,
        pseudo_blinding_2,
        pseudo_commitment_2)

    // --- Step 4: Assemble the transaction ------------------------------
    // Pack everything together. This is what gets broadcast to the network.

    RETURN Transaction {
        // Two new outputs (coins being created)
        outputs: [
            {
                one_time_key:     one_time_key_1,      // stealth address for Bob
                commitment:       commitment_1,         // hides "9 coins"
                encrypted_amount: encrypted_amount_1    // amount encrypted to Bob
            },
            {
                one_time_key:     one_time_key_2,      // stealth address for Alice (change)
                commitment:       commitment_2,         // hides "1 coin"
                encrypted_amount: encrypted_amount_2    // amount encrypted to Alice
            }
        ],

        // Two input proofs (coins being spent)
        inputs: [
            {
                ring_keys:        ring_keys_1,          // 11 public keys (real + 10 decoys)
                ring_commitments: ring_commitments_1,   // 11 Pedersen commitments
                signature:        sig_1,                // CLSAG ring signature (~416 bytes)
                key_image:        key_image_1           // unique tag for double-spend detection
            },
            {
                ring_keys:        ring_keys_2,          // 11 public keys (real + 10 decoys)
                ring_commitments: ring_commitments_2,   // 11 Pedersen commitments
                signature:        sig_2,                // CLSAG ring signature (~416 bytes)
                key_image:        key_image_2           // unique tag for double-spend detection
            }
        ],

        // Pseudo-commitments (needed for balance check)
        pseudo_commitments: [
            pseudo_commitment_1,   // hides "7 coins" with balanced blinding
            pseudo_commitment_2    // hides "3 coins" with balanced blinding
        ],

        // One compact range proof covering both outputs
        range_proof: range_proof,   // BP++ proof (~580 bytes for 2 outputs)

        // Public fee
        fee: 0
    }
```

### Verification (Network)

```
FUNCTION verify_transaction(tx, spent_key_images):
    //
    // The network checks Alice's transaction.
    // It can verify everything is correct WITHOUT learning:
    //   - which ring member is the real signer (hidden by CLSAG)
    //   - how much was sent (hidden by Pedersen commitments)
    //   - who the recipient is (hidden by stealth addresses)
    //

    // --- Check 1: No double-spending -------------------------------------
    // Each key image is a unique tag for a specific coin. If the
    // network has seen this tag before, the coin was already spent.

    key_image_1 = tx.inputs[0].key_image   // 32-byte point
    key_image_2 = tx.inputs[1].key_image   // 32-byte point

    IF key_image_1 IN spent_key_images:
        RETURN false   // "This coin was already spent!"
    IF key_image_2 IN spent_key_images:
        RETURN false

    // --- Check 2: Amounts balance ----------------------------------------
    // Verify: sum(pseudo_commitments) == sum(output_commitments) + fee * H
    //
    // In our example:
    //   (pseudo_1 + pseudo_2) - (commitment_1 + commitment_2) - 0*H
    //   should equal the identity point (zero).
    //
    // This works because the blindings were chosen to cancel out,
    // and 7 + 3 == 9 + 1 + 0.

    balance_check = tx.pseudo_commitments[0] + tx.pseudo_commitments[1]
                  - tx.outputs[0].commitment - tx.outputs[1].commitment
                  - tx.fee * H

    IF balance_check != identity_point:
        RETURN false   // "The amounts don't add up!"

    // --- Check 3: Range proof --------------------------------------------
    // Verify that every output amount is in [0, 2^64).
    // Without this, Alice could commit to a negative amount and
    // create coins out of thin air.

    output_commitments = [
        tx.outputs[0].commitment,   // commitment hiding 9 coins
        tx.outputs[1].commitment    // commitment hiding 1 coin
    ]

    IF NOT BulletproofsPP::verify(tx.range_proof, output_commitments):
        RETURN false   // "Some output amount might be negative!"

    // --- Check 4: Ring signatures ----------------------------------------
    // For each input, verify the CLSAG proves the signer owns one
    // of the 11 keys in the ring, without revealing which one.

    tx_prefix_hash = hash(
        tx.outputs[0].one_time_key, tx.outputs[0].commitment, tx.outputs[0].encrypted_amount,
        tx.outputs[1].one_time_key, tx.outputs[1].commitment, tx.outputs[1].encrypted_amount,
        tx.fee)

    IF NOT CLSAG::check_ring_signature(
            tx_prefix_hash,
            tx.inputs[0].key_image,
            tx.inputs[0].ring_keys,
            tx.inputs[0].signature,
            tx.inputs[0].ring_commitments):
        RETURN false   // "Input #1: invalid ring signature!"

    IF NOT CLSAG::check_ring_signature(
            tx_prefix_hash,
            tx.inputs[1].key_image,
            tx.inputs[1].ring_keys,
            tx.inputs[1].signature,
            tx.inputs[1].ring_commitments):
        RETURN false   // "Input #2: invalid ring signature!"

    // --- Check 5: Accept the transaction ---------------------------------
    // Everything checks out! Record the key images so we can detect
    // if Alice ever tries to spend these same coins again.

    spent_key_images.add(key_image_1)
    spent_key_images.add(key_image_2)

    RETURN true   // "Transaction is valid!"
```

### Visual: Ring Signature Anonymity

```
Ring for input #1 (N=11):
  +----------------------------------------------------------+
  |  K0  K1  K2  K3  K4  K5  K6  K7  K8  K9  K10            |
  |  o   o   o   o   *   o   o   o   o   o   o               |
  |                   |                                      |
  |              real signer                                 |
  |         (but which one? nobody knows!)                   |
  |                                                          |
  |  The CLSAG signature proves exactly ONE of these 11      |
  |  public keys was used, without revealing which.          |
  |  The key image I links this spend to future attempts     |
  |  to double-spend the same output.                        |
  +----------------------------------------------------------+

Ring for input #2 (N=11):
  +----------------------------------------------------------+
  |  K0  K1  K2  K3  K4  K5  K6  K7  K8  K9  K10            |
  |  o   o   o   o   o   o   o   o   o   *   o               |
  |                                       |                  |
  |                                  real signer             |
  |                                                          |
  |  Different ring, different decoys, different position.   |
  |  Each input has its own independent anonymity set.       |
  +----------------------------------------------------------+

What the verifier sees:              What stays hidden:
  [Y] Key images are unique            [N] Which ring member is real
      (no double-spending)                 (CLSAG hides the signer)
  [Y] Amounts balance                  [N] The actual amounts
      (Pedersen math guarantees it)        (commitments hide them)
  [Y] Amounts are non-negative         [N] Who sent or received
      (range proof)                        (stealth addresses)
  [Y] Each input is authorized
      (ring signature is valid)
```

---

## Mode Binding

CLSAG runs in one of two modes per signature: **plain ring** (no commitment binding) or **commitment-binding ring** (with `commitment_image`, `pseudo_commitment`, and a parallel `commitments` vector). Both directions of mode mismatch are rejected explicitly by two complementary mechanisms:

**Strict mode-mismatch reject** at the top of every `check_ring_signature` and `generate_ring_signature` entry point. The signer's mode is recovered from the signature's own fields (`commitment_image.valid() && pseudo_commitment.valid()`); the caller's stated mode is recovered from the shape of the `commitments` vector (`!commitments.empty()` for verify; partial-vs-full supply of the four commitment-mode arguments for sign). Disagreement in either direction is a hard `false` return. Mismatched ring/commitments sizes are also rejected explicitly.

**Transcript binding** of an explicit `uint8_t` mode tag (`0x00` plain, `0x01` commit) into all three CLSAG transcripts: `mu_P` (`CLSAG_DOMAIN_0`), `mu_C` (`CLSAG_DOMAIN_2`), and the challenge chain (`CLSAG_DOMAIN_1`). The tag is absorbed immediately after the domain separator, in both sign and verify, so `h0` itself becomes a function of the mode. Even if a future refactor removed the runtime mismatch check, the challenge chain would not close on a mismatched mode and the ring signature would fail to verify.

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 5-7 | CLSAG |

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

### Target `clsag`

Source: [`src/fuzz/fuzz_target_clsag.cpp`](../../src/fuzz/fuzz_target_clsag.cpp)

Entry points exercised:

- `Crypto::RingSignature::CLSAG::generate_ring_signature (plain and commitment modes)`
- `Crypto::RingSignature::CLSAG::check_ring_signature (plain and commitment modes)`
- `clsag_signature_t deserialization (binary + JSON)`

---

## References

| Topic | Link |
|-------|------|
| CLSAG ring signatures | [Goodell et al., 2019 (ePrint 2019/654)][clsag-paper] |

[clsag-paper]: https://eprint.iacr.org/2019/654
