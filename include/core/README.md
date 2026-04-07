# Core Module

This directory contains the foundation layer of the crypto library --
initialization, configuration, domain separation constants, and the core
cryptographic utility functions that every other module depends on. If the
library were a house, this is the concrete slab and load-bearing walls.

All headers are accessible through `#include <crypto.h>`.

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | The foundation in plain English |
| [crypto_common.h](#crypto_commonh) | Initialization, keys, stealth addresses, AES, key images |
| [crypto_config.h](#crypto_configh) | Compile-time configuration macros |
| [crypto_constants.h](#crypto_constantsh) | Domain separation constants (indices 0-27) |
| [Math Helpers](#math-helpers) | Power-of-2 rounding, base-2 exponent (header-only) |
| [References](#references) | Papers and standards |

---

## How It Works (ELI5)

Think of this module as the **electrical panel** in a building. Before you
flip any light switch (sign a message, create a proof, derive a key), the
panel has to be wired up and turned on. That is what `Crypto::init()` does --
it detects your CPU's SIMD capabilities (AVX2, AVX-512 IFMA, or baseline)
and connects the fastest implementation behind every low-level operation.

```
  YOUR CPU
  ┌─────────────────────────────────────────────┐
  │                                             │
  │  Crypto::init()                             │
  │    "Which SIMD instructions do I have?"     │
  │                                             │
  │    ┌──────────┐  ┌──────────┐  ┌─────────┐  │
  │    │ Portable │  │  AVX2    │  │  IFMA   │  │
  │    │ (always) │  │ Haswell+ │  │  IceLk+ │  │
  │    └────┬─────┘  └────┬─────┘  └────┬────┘  │
  │         │             │             │       │
  │         └──────┬──────┴─────────────┘       │
  │                v                            │
  │         Best backend selected               │
  │         (once, at startup)                  │
  └─────────────────────────────────────────────┘
```

Beyond initialization, this module provides the **everyday toolkit**:

- **Key generation** -- create random Ed25519 key pairs.
- **Stealth addresses** -- one-time output keys so that an observer
  cannot link payments to a recipient's public address.
- **Key images** -- deterministic fingerprints for double-spend detection.
- **AES encryption** -- password-based AES-256-CBC for protecting secrets at rest.
- **Domain constants** -- per-subsystem salt values that keep every proof and
  signature scheme in its own hash domain, like separate decks of cards at
  the same poker table.

---

## crypto_common.h

**Header**: [`crypto_common.h`](crypto_common.h)
**Namespace**: `Crypto`

### Initialization

```cpp
// Option 1: Heuristic SIMD dispatch (fast, picks IFMA > AVX2 > baseline)
Crypto::init();

// Option 2: Benchmark all backends, select fastest (~1-2 seconds)
Crypto::autotune();
```

Both functions are thread-safe and idempotent. Call one of them once at
program startup before any cryptographic operations.

### Key Generation

Generates random Ed25519 key pairs. The secret key `sk` is a random scalar;
the public key `pk` is `sk * G` (the scalar multiplied by the Ed25519 base
point). These keys are **not** seed-recoverable -- if you lose `sk`, there is
no mnemonic phrase to get it back. For recoverable keys, use HD key derivation
from a BIP-39 seed (see `helpers/hd_keys.h` and `types/seed_t.h`).

```cpp
// Single random key pair: pk = public key (point), sk = secret key (scalar)
auto [pk, sk] = Crypto::generate_keys();

// Multiple random key pairs at once
auto [pks, sks] = Crypto::generate_keys_m(count);
// pks[i] = sks[i] * G for all i
```

### Key Derivation (Stealth Addresses)

The stealth address protocol lets a sender create one-time output keys that
only the recipient can spend, without any observable link between the
recipient's public address and the output.

**ELI5**: Bob has a public address, but if Alice sends directly to it, everyone
on the network can see "someone paid Bob." Stealth addresses fix this. Each
time Alice pays Bob, she creates a brand-new one-time address just for that
payment. This one-time address looks completely random to everyone on the
network -- nobody can tell it belongs to Bob. But Bob can scan every new
address and recognize which ones are secretly his, using his private view key.
When he wants to spend the coins, he uses his private spend key.

**How it works:** Bob's public address contains two keys -- a *spend public key*
(A) and a *view public key* (B). The spend key authorizes spending; the view
key lets Bob (or an auditor with the view secret) scan for incoming payments
without being able to spend them.

```
Sender (Alice) knows: (A, B) = Bob's (spend pubkey, view pubkey)
Sender picks:         random ephemeral scalar r

                  Sender (Alice)                  Recipient (Bob)
                    |                                |
  R = r*G         (1) publish R in transaction       |
                    |                                |
  D = r*B         (2) D = b*R  (same ECDH secret)    |
                    |                                |
  Ds = H(D||idx)  (3) Ds = H(D||idx)                 |
                    |                                |
  P = Ds*G + A    (4) p = Ds + a  (can spend P)      |
```

The `output_index` (idx) is a per-output counter within a single transaction.
If Alice creates two outputs in the same transaction (e.g., one for Bob and
one for change), each gets a different index (0, 1) so they produce different
one-time keys even if the recipient is the same.

```cpp
// ─── Sender (Alice) creates a one-time output key for Bob ───────
// Alice knows Bob's public view key (B) and has picked a random scalar r.
// She computes the ECDH shared secret from r and Bob's view public key.
auto r = scalar_t::random();            // Alice's ephemeral secret
auto R = r * Crypto::G;                 // published in the transaction
auto D = Crypto::generate_key_derivation(
    bob_view_public,                    // Bob's public view key (B)
    r);                                 // Alice's ephemeral secret

// Derive the per-output scalar (different for each output in a tx)
auto Ds = Crypto::derivation_to_scalar(D, output_index);

// Compute the one-time output public key that only Bob can spend
auto P = Crypto::derive_public_key(Ds, bob_spend_public);  // P = Ds*G + A

// ─── Recipient (Bob) detects and spends the output ──────────────
// Bob sees R in the transaction. He computes the same shared secret
// using his private view key (b) and Alice's published R.
auto D_bob = Crypto::generate_key_derivation(
    R,                                  // Alice's ephemeral public key
    bob_view_secret);                   // Bob's private view key (b)

// Bob derives the same Ds and reconstructs P to check if it matches
auto Ds_bob = Crypto::derivation_to_scalar(D_bob, output_index);
auto P_check = Crypto::derive_public_key(Ds_bob, bob_spend_public);
// If P_check == P, this output belongs to Bob!

// Bob derives the one-time secret key to spend this output
auto p = Crypto::derive_secret_key(Ds_bob, bob_spend_secret);
// p is the secret key for P: p*G == P

// ─── Utility: recover base spend key from an output key ─────────
// Given a derivation and output index, reverse the derivation to get
// the base spend public key. Used when scanning to confirm ownership.
auto A = Crypto::underive_public_key(D_bob, output_index, P);
// A == bob_spend_public
```

**Alternative uses:** Stealth addresses are not limited to financial
transactions. They apply anywhere a sender needs to deliver data to a
recipient without observers being able to link the delivery to the
recipient's known public identity -- for example, private messaging systems,
anonymous credential issuance, or unlinkable data delivery in mixnets.

### Key Images

A key image is a deterministic, unique tag derived from a one-time output key.
When someone spends an output, the key image is published alongside the
signature. If the same output is ever spent again (even in a different
transaction with different ring members), the key image will be identical.
The network maintains a set of all seen key images and rejects any
transaction that reuses one.

**ELI5**: Think of a key image like a serial number stamped on a coin. The
serial number is baked into the coin itself -- you cannot change it or remove
it. Every time someone tries to spend that coin, the cashier records the serial
number. If the same serial number ever appears again, the cashier knows it is
a counterfeit (double-spend) and rejects it. Crucially, the serial number
reveals nothing about *who* spent the coin -- only that *this specific coin*
was spent before.

The key image is derived from the one-time secret key that controls a specific
output (created during stealth address derivation above). Different outputs
controlled by the same wallet produce different key images, because each
output has a different one-time key.

```cpp
// The one-time output key P and its secret key p come from stealth
// address derivation (see Key Derivation above).
// P = Ds*G + A       (public, stored on the ledger as the output key)
// p = Ds + a         (secret, known only to the recipient)

// Standard key image: I = p * Hp(P)
// Hp(P) is a hash-to-point of the public key -- a deterministic curve point
// unique to P. Multiplying by p makes I deterministic for this output.
auto I = Crypto::generate_key_image(P, p);

// Alternate form used by Triptych: I = (1/p) * U
// U is a fixed generator point. This formula is algebraically different
// but serves the same purpose -- a unique, deterministic tag per output.
auto I2 = Crypto::generate_key_image_v2(p);
```

**Alternative uses:** Key images (or the concept of deterministic unlinkable
tags) can be used anywhere you need to detect if a secret holder has performed
an action more than once, without revealing their identity. Examples include
anonymous e-voting (detect double-voting), anonymous token redemption, or
single-use credential systems.

### AES Encryption

Password-based AES-128-CBC with PBKDF2-SHA3-512 key derivation and
HMAC-SHA3-256 authentication. Used to protect sensitive data at rest --
for example, encrypting a wallet's secret keys or mnemonic seed before
storing them on disk. The password is never stored; it is stretched via
PBKDF2 into 48 bytes (16-byte AES key + 16-byte HMAC key + 16-byte IV),
making brute-force attacks computationally expensive.

```cpp
// Encrypt a secret (e.g., a hex-encoded private key) with a user password.
// The result is a hex-encoded string safe for storage in a config file.
auto ciphertext = Crypto::AES::encrypt(plaintext, password);

// Decrypt with the same password to recover the original plaintext.
auto recovered  = Crypto::AES::decrypt(ciphertext, password);

// Use a higher iteration count for stronger protection (slower to brute-force).
// Default is CRYPTO_PBKDF2_ITERATIONS = 10000.
auto ct = Crypto::AES::encrypt(plaintext, password, 100000);
```

### Validation Helpers

```cpp
bool ok = Crypto::check_point(bytes);   // valid Ed25519 curve point?
bool ok = Crypto::check_scalar(bytes);  // reduced scalar in [0, l)?
```

---

## crypto_config.h

**Header**: [`crypto_config.h`](crypto_config.h)

Compile-time configuration macros with sensible defaults. Override any macro
by defining it before including `crypto.h` or via `-DMACRO=value` compiler
flags.

| Macro | Default | Description |
|-------|---------|-------------|
| `CRYPTO_BASE58_CHECKSUM_SIZE` | `4` | Bytes of SHA-3 hash used as Base58 checksum |
| `CRYPTO_PBKDF2_ITERATIONS` | `10000` | Default PBKDF2 iteration count for AES |
| `CRYPTO_ENTROPY_BYTES` | `32` | Entropy size (32 = 256-bit / 24-word mnemonic) |
| `CRYPTO_MINIMUM_SEED_TIMESTAMP` | `1640995200` | Earliest valid seed timestamp (2022-01-01) |
| `CRYPTO_MAXIMUM_SEED_TIMESTAMP` | `10413792000` | Latest valid seed timestamp |

Benchmark-specific (only relevant when `BUILD_BENCHMARK=ON`):

| Macro | Default | Description |
|-------|---------|-------------|
| `BENCHMARK_PERFORMANCE_ITERATIONS` | `1000` | Base iteration count per measurement |
| `BENCHMARK_PERFORMANCE_ITERATIONS_LONG_MULTIPLIER` | `60` | Multiplier for fast ops |
| `BENCHMARK_PREFIX_WIDTH` | `70` | Label column width (chars) |
| `BENCHMARK_COLUMN_WIDTH` | `10` | Numeric column width (chars) |
| `BENCHMARK_PRECISION` | `3` | Decimal places for timings |

---

## crypto_constants.h

**Header**: [`crypto_constants.h`](crypto_constants.h)

Deterministic domain separation constants derived from a fixed root seed
via iterated SHA-3 hashing. Each cryptographic subsystem uses its own
constants to prevent cross-protocol scalar collisions.

### How It Works

**ELI5**: Imagine you are running a dozen different card games at the same
table. To prevent cheating, you need separate decks for each game -- if
someone swaps a card between games, the colors will not match. Domain
constants work the same way: each proof system (CLSAG, Bulletproofs, etc.)
gets its own "deck color" derived from a master seed. A scalar from the
CLSAG transcript can never accidentally collide with one from Bulletproofs,
because they started from different seeds.

**Why this matters:** Without domain separation, a proof generated for one
system could potentially satisfy a verification equation in another system.
For example, an attacker could try to take a valid CLSAG ring signature
and repurpose it as a fake Bulletproof. Domain constants make this impossible
by ensuring each system's challenge values live in a completely separate
mathematical space.

```
SALT_DOMAIN = fixed 32-byte scalar
               |
               v
 generate_salt_scalar(index) = sha3_slow(SALT_DOMAIN, index).scalar()
 generate_salt_point(index)  = sha3_slow(SALT_DOMAIN, index).point()
```

The `sha3_slow` function iterates SHA-3 `index` times, making each constant
deterministic but computationally independent. All constants are computed at
first use and cached.

### Domain Constant Map

```
Index   Subsystem                    Constants
-----   ---------                    ---------
 0      Key Derivation               DERIVATION_DOMAIN_0
 1-2    Wallet Keys                  SPEND_KEY_DOMAIN_0, VIEW_KEY_DOMAIN_0
 3      Ed25519 Signatures           SIGNATURE_DOMAIN_0
 4      Borromean                    BORROMEAN_DOMAIN_0
 5-7    CLSAG                        CLSAG_DOMAIN_0..2
 8-9    RingCT Masks                 DOMAIN_COMMITMENT_MASK_0, DOMAIN_AMOUNT_MASK_0
10-11   Triptych                     TRIPTYCH_DOMAIN_0 (s), TRIPTYCH_DOMAIN_1 (p)
12-14   Bulletproofs                 BULLETPROOFS_DOMAIN_0 (s), _1 (p), _2 (p)
15-17   Bulletproofs+                BULLETPROOFS_PLUS_DOMAIN_0 (s), _1 (p), _2 (p)
18      Audit Proofs                 OUTPUT_PROOF_DOMAIN
19      Transcript Base              TRANSCRIPT_BASE
20-22   Bulletproofs++               BULLETPROOFS_PP_DOMAIN_0 (s), _1 (p), _2 (p)
23-24   MLSAG                        MLSAG_DOMAIN_0..1
25      DLEQ                         DLEQ_DOMAIN_0
26      Adapter Signatures           ADAPTER_DOMAIN_0
27      VRF                          VRF_DOMAIN_0

(s) = scalar via generate_salt_scalar()
(p) = point via generate_salt_point()
All unmarked entries are scalars.
Next available index: 28
```

### Usage

Constants seed Fiat-Shamir transcripts, derive generator points, and
separate key derivation domains:

```cpp
// CLSAG transcript seeded with its own domain constant
scalar_transcript_t transcript(CLSAG_DOMAIN_0, tx_prefix_hash, ring_public_keys);
transcript.update(commitment_A);
auto challenge = transcript.challenge();

// Generator points for Bulletproofs++ derived from domain points
auto G = BULLETPROOFS_PP_DOMAIN_1;  // point_t
auto H = BULLETPROOFS_PP_DOMAIN_2;  // point_t
```

---

## Modules Moved to Separate Directories

| Module | Directory | Documentation |
|--------|-----------|---------------|
| DLEQ Proofs | [`dleq/`](../dleq/) | [`dleq/README.md`](../dleq/README.md) |

---

## Math Helpers

**Header**: [`helpers/math_helpers.h`](../helpers/math_helpers.h) (header-only, lives in `helpers/`)

Small utility functions used internally by proof systems:

```cpp
// Round up to next power of 2
size_t n = Crypto::pow2_round(200);  // returns 256

// Check if value is a power of 2 and get its exponent
auto [is_pow2, exponent] = Crypto::calculate_base2_exponent(256);
// is_pow2 == true, exponent == 8
```

These are header-only and included transitively through `crypto_common.h`.

---

## References

| Topic | Link |
|-------|------|
| Ed25519 specification | [RFC 8032 -- Edwards-Curve Digital Signature Algorithm][rfc8032] |
| Ristretto255 | [RFC 9496 -- The ristretto255 and decaf448 Groups][rfc9496] |

[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032.html
[rfc9496]: https://www.rfc-editor.org/rfc/rfc9496.html
