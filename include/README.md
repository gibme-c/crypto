# Crypto Library API Reference

This is the public API for the standalone C++17 cryptographic primitive
library built around Ed25519 elliptic curve operations. Everything is
accessed through a single header:

```cpp
#include <crypto.h>
```

Link against the `crypto-static` CMake target to pull in all dependencies.

---

## Table of Contents

| Section | What It Covers |
|---------|---------------|
| [How It Works (ELI5)](#how-it-works-eli5) | The library in plain English |
| [Getting Started](#getting-started) | Initialization, SIMD dispatch, first steps |
| [crypto.h](#cryptoh) | Unified include (pulls in the entire API) |
| [Subdirectory Guides](#subdirectory-guides) | Links to per-module documentation |
| [References](#references) | Papers, standards, and further reading |

---

## How It Works (ELI5)

Imagine you're building a secure postal system for a city. People need
to send letters and parcels without anyone reading them, without anyone
forging the sender's name, and without anyone spending the same
postage stamp twice.

This library is the **toolbox** for building that system. Each drawer
in the toolbox holds a different kind of tool:

```
       THE CRYPTO TOOLBOX
  ┌─────────────────────────────────────┐
  │                                     │
  │  ┌──────────┐  Keys & Addresses     │
  │  │  🔑 🔑  │  Create identities    │
  │  │  🔑 🔑  │  (like making a       │
  │  └──────────┘   return-address      │
  │                  stamp & matching   │
  │                  wax seal)          │
  │                                     │
  │  ┌──────────┐  Signatures           │
  │  │  ✍️ ✍️  │  Prove authorship     │
  │  │  ✍️ ✍️  │  (like a wax seal     │
  │  └──────────┘   that can't be       │
  │                  forged -- and      │
  │                  ring signatures    │
  │                  hide WHICH seal    │
  │                  was used)          │
  │                                     │
  │  ┌──────────┐  Commitments          │
  │  │  📦 📦  │  Hide amounts         │
  │  │  📦 📦  │  (like opaque         │
  │  └──────────┘   envelopes where     │
  │                  the math proves    │
  │                  the totals add     │
  │                  up without         │
  │                  opening them)      │
  │                                     │
  │  ┌──────────┐  Proofs               │
  │  │  📜 📜  │  Prove facts about    │
  │  │  📜 📜  │  hidden values        │
  │  └──────────┘  (like proving the    │
  │                  amount inside a    │
  │                  sealed envelope    │
  │                  is not negative    │
  │                  without opening it)│
  │                                     │
  │  ┌──────────┐  Encoding             │
  │  │  🔤 🔤  │  Human-readable       │
  │  │  🔤 🔤  │  formats              │
  │  └──────────┘  (like writing a      │
  │                  32-byte address    │
  │                  as words you can   │
  │                  read on the phone) │
  └─────────────────────────────────────┘
```

**Here's how a typical transaction works at a high level:**

```
Alice wants to send 5 coins to Bob.

1. Alice uses Bob's public address to create a fresh, one-time
   delivery address (a "stealth address") just for this payment.
   This address looks random to everyone -- only Bob can recognize
   it as his, using his private view key.

2. She puts 5 coins in an opaque envelope (Pedersen commitment)
   and proves the amount is non-negative (range proof).

3. She stamps the envelope with a ring signature -- a special wax
   seal that proves "one of these 11 people sent this" without
   revealing which one. The stamp also includes a unique serial
   number (key image) that the post office records so Alice can't
   send the same coins twice.

4. She drops the letter in the mailbox. The post office checks:
   - Has this serial number been used before?  (no double-spending)
   - Do the amounts add up?                   (conservation)
   - Is the wax seal valid?                   (authorization)
   - Is the amount non-negative?              (no counterfeiting)

   All four checks pass without learning WHO sent the letter,
   HOW MUCH was sent, or WHO received it.
```

The library provides every tool needed to build step 1-4: key
generation, stealth addresses, Pedersen commitments, range proofs
(Bulletproofs/BP+/BP++), ring signatures (CLSAG/Triptych), and key images.

---

## Getting Started

### Initialization

The library uses a SIMD-accelerated backend for Ed25519 operations.
Call one of the initialization functions before using any cryptographic
operations:

```cpp
#include <crypto.h>

int main()
{
    // Option 1: Heuristic dispatch (fast, picks IFMA > AVX2 > baseline)
    Crypto::init();

    // Option 2: Benchmark all backends, select fastest (~1-2s)
    Crypto::autotune();

    // Now use the library (see examples below)
}
```

Both functions are thread-safe and idempotent -- calling them multiple
times is harmless. `init()` uses compile-time CPUID heuristics while
`autotune()` runs actual benchmarks to find the fastest backend for the
current CPU.

### Quick Example

```cpp
#include <crypto.h>

int main()
{
    Crypto::init();

    // Generate a random key pair
    auto [public_key, secret_key] = Crypto::generate_keys();

    // Hash some data
    auto digest = hash_t::sha3("hello", 5);

    // Sign and verify
    auto sig = Crypto::Signature::generate_signature(digest, secret_key);
    bool valid = Crypto::Signature::check_signature(digest, public_key, sig);

    // Create a Pedersen commitment: C = blind*G + 42*H
    auto blind = blinding_factor_t::random();
    auto commitment = Crypto::RingCT::generate_pedersen_commitment(blind, 42);

    // Prove the committed amount is in [0, 2^64)
    auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPP::prove({42}, {blind});
    bool range_ok = Crypto::RangeProofs::BulletproofsPP::verify(proof, commitments);
}
```

### Scenario: Alice Generates a Key Pair and Signs a Message

Here's a more complete walkthrough with concrete values:

```
FUNCTION alice_signs_a_message():
    // Alice wants to prove she authored a document.
    // She generates a key pair, signs the document's hash,
    // and publishes the signature alongside her public key.

    // ─── Step 1: Generate keys ──────────────────────────────────
    // generate_keys() returns (public_key_t, scalar_t).
    // The secret key is a random scalar (a 32-byte number mod the
    // curve order). The public key is derived by multiplying the
    // secret scalar by the Ed25519 base point G.
    //
    //   secret_key  = random scalar
    //   public_key  = secret_key * G   (a point on the curve)
    //
    // Alice keeps secret_key private. She publishes public_key.

    [public_key, secret_key] = Crypto::generate_keys()
    // public_key = 32 bytes  (a curve point, safe to share)
    // secret_key = 32 bytes  (a scalar, NEVER share this)

    // ─── Step 2: Hash the document ──────────────────────────────
    // SHA3-256 produces a 32-byte digest that uniquely fingerprints
    // the document. Even a 1-bit change produces a completely
    // different digest.

    document = "I, Alice, agree to pay Bob 5 coins on 2024-01-15."
    digest = hash_t::sha3(document, document.length())
    // digest = 32 bytes, e.g. "b7e3...91"

    // ─── Step 3: Sign ────────────────────────────────────────────
    // The signature is a Schnorr proof: Alice picks a random nonce k,
    // computes a challenge from (digest, k*G), and responds with
    // s = k - challenge * secret_scalar.
    //
    // The resulting signature is 64 bytes: (challenge, response).

    sig = Crypto::Signature::generate_signature(digest, secret_key)
    // sig = 64 bytes

    // ─── Step 4: Anyone can verify ───────────────────────────────
    // The verifier recomputes the challenge from (digest, public_key,
    // response) and checks it matches the challenge in the signature.
    // This proves Alice knew the secret key without revealing it.

    valid = Crypto::Signature::check_signature(digest, public_key, sig)
    // valid == true

    // If someone tampers with the document:
    tampered = hash_t::sha3("I agree to pay Bob 50 coins", 27)
    still_valid = Crypto::Signature::check_signature(tampered, public_key, sig)
    // still_valid == false  (signature is bound to the original digest)
```

---

## crypto.h

**Header**: [`crypto.h`](crypto.h)

The unified include that pulls in the entire public API. Including this
single header gives you access to all types, signatures, proofs, encoding,
helpers, and constants. There is no need to include individual module
headers unless you want to minimize compilation dependencies.

```
crypto.h
  |-- core/                 crypto_common, crypto_config, crypto_constants
  |-- types/                All data types (points, scalars, vectors)
  |-- helpers/              Transcripts, CSPRNG, HD keys, Lagrange,
  |                         wide reduction, math, utilities
  |-- dleq/                 Discrete Log Equality (Chaum-Pedersen) proofs
  |-- base58/               Base58 and CryptoNote Base58
  |-- addresses/            Public key address encoding
  |-- mnemonics/            BIP-39 mnemonic word phrases (10 languages)
  |-- slip39/               SLIP-39 Shamir's Secret Sharing
  |-- ed25519/              Ed25519 basic signatures and RFC 8032
  |-- borromean/            Borromean ring signatures
  |-- clsag/                CLSAG ring signatures
  |-- mlsag/                MLSAG ring signatures
  |-- triptych/             Triptych logarithmic ring signatures
  |-- adapter_signature/    Adapter pre-signatures for atomic swaps
  |-- ringct/               RingCT Pedersen commitments
  |-- bulletproofs/         Bulletproof range proofs
  |-- bulletproofsplus/     Bulletproofs+ range proofs
  |-- bulletproofspp/       Bulletproofs++ range proofs
  |-- vrf/                  Verifiable Random Functions
  |-- merkle/               Merkle hash trees
  |-- integration/          Audit proofs (proof-of-reserves)
```

---

## Subdirectory Guides

Each subdirectory has its own README with detailed API documentation,
diagrams, ELI5 explanations, and examples:

| Directory | README | Contents |
|-----------|--------|----------|
| [`core/`](core/) | [Core README](core/README.md) | crypto_common, crypto_config, crypto_constants, math helpers |
| [`types/`](types/) | [Types README](types/README.md) | All data types (points, scalars, vectors) |
| [`helpers/`](helpers/) | [Helpers README](helpers/README.md) | Transcripts, CSPRNG, HD keys, Lagrange, wide reduction, constant-time, utilities |
| [`dleq/`](dleq/) | [DLEQ README](dleq/README.md) | Discrete Log Equality (Chaum-Pedersen) proofs |
| [`base58/`](base58/) | [Base58 README](base58/README.md) | Standard Base58 and CryptoNote Base58 encoding |
| [`addresses/`](addresses/) | [Addresses README](addresses/README.md) | Public key address encoding (single and dual key) |
| [`mnemonics/`](mnemonics/) | [Mnemonics README](mnemonics/README.md) | BIP-39 mnemonic word phrases (10 languages) |
| [`slip39/`](slip39/) | [SLIP-39 README](slip39/README.md) | SLIP-39 Shamir's Secret Sharing |
| [`ed25519/`](ed25519/) | [Ed25519 README](ed25519/README.md) | Ed25519 basic signatures and RFC 8032 |
| [`borromean/`](borromean/) | [Borromean README](borromean/README.md) | Borromean ring signatures |
| [`clsag/`](clsag/) | [CLSAG README](clsag/README.md) | CLSAG ring signatures |
| [`mlsag/`](mlsag/) | [MLSAG README](mlsag/README.md) | MLSAG ring signatures |
| [`triptych/`](triptych/) | [Triptych README](triptych/README.md) | Triptych logarithmic ring signatures |
| [`adapter_signature/`](adapter_signature/) | [Adapter Signature README](adapter_signature/README.md) | Adapter pre-signatures for atomic swaps |
| [`ringct/`](ringct/) | [RingCT README](ringct/README.md) | RingCT Pedersen commitments |
| [`bulletproofs/`](bulletproofs/) | [Bulletproofs README](bulletproofs/README.md) | Bulletproof range proofs |
| [`bulletproofsplus/`](bulletproofsplus/) | [Bulletproofs+ README](bulletproofsplus/README.md) | Bulletproofs+ range proofs |
| [`bulletproofspp/`](bulletproofspp/) | [Bulletproofs++ README](bulletproofspp/README.md) | Bulletproofs++ range proofs |
| [`vrf/`](vrf/) | [VRF README](vrf/README.md) | Verifiable Random Functions (native and RFC 9381) |
| [`merkle/`](merkle/) | [Merkle README](merkle/README.md) | Merkle hash trees |
| [`integration/`](integration/) | [Integration README](integration/README.md) | Audit proofs (proof-of-reserves) |

---

## External Dependencies

All dependencies are statically linked via the `crypto-thirdparty` CMake
interface target:

| Library | Purpose |
|---------|---------|
| **ed25519** | Ed25519 primitives, ristretto255, MSM, SIMD backends |
| **ranshaw** | Ran/Shaw 2-cycle curves |
| **argon2** | Argon2d/i/id password hashing |
| **tinyaes** | AES encryption (CBC/CTR/GCM) with SIMD backends |
| **serializationcpp** | Binary/JSON/hex serialization framework |

---

## Build Options

| CMake Option | Default | Effect |
|-------------|---------|--------|
| `BUILD_TESTS` | OFF | Build test and benchmark binaries |
| `BUILD_SHARED` | OFF | Build shared library alongside static |
| `ENGLISH_ONLY` | OFF | Exclude non-English BIP-39 word lists |
| `DEBUG_PRINT` | OFF | Enable debug output macros |
| `ARCH` | native | Target CPU architecture (`-march` value) |

---

## References

| Topic | Link |
|-------|------|
| Ed25519 specification | [RFC 8032 -- Edwards-Curve Digital Signature Algorithm][rfc8032] |
| BIP-39 mnemonic encoding | [BIP-0039: Mnemonic code for generating deterministic keys][bip39] |
| BIP-32 HD key derivation | [BIP-0032: Hierarchical Deterministic Wallets][bip32] |
| SLIP-10 Ed25519 derivation | [SLIP-0010: Universal private key derivation][slip10] |
| Pedersen commitments | [Pedersen, 1991: Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing][pedersen] |
| Bulletproofs | [Bunz et al., 2018 (ePrint 2017/1066)][bp] |
| Bulletproofs+ | [Chung et al., 2020 (ePrint 2020/735)][bpplus] |
| Bulletproofs++ | [Habock, 2022 (ePrint 2022/510)][bppp] |
| CLSAG | [Goodell et al., 2019 (ePrint 2019/654)][clsag] |
| Triptych | [Noether, 2020 (ePrint 2020/018)][triptych] |
| VRF | [RFC 9381 -- ECVRF-EDWARDS25519-SHA512-ELL2][rfc9381] |
| Ristretto255 | [RFC 9496 -- The ristretto255 and decaf448 Groups][rfc9496] |
| Shamir's Secret Sharing | [Shamir, 1979: How to Share a Secret][shamir] |

[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032.html
[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[bip32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[slip10]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[pedersen]: https://link.springer.com/chapter/10.1007/3-540-46766-1_9
[bp]: https://eprint.iacr.org/2017/1066
[bpplus]: https://eprint.iacr.org/2020/735
[bppp]: https://eprint.iacr.org/2022/510
[clsag]: https://eprint.iacr.org/2019/654
[triptych]: https://eprint.iacr.org/2020/018
[rfc9381]: https://www.rfc-editor.org/rfc/rfc9381.html
[rfc9496]: https://www.rfc-editor.org/rfc/rfc9496.html
[shamir]: https://dl.acm.org/doi/10.1145/359168.359176
