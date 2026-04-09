# Ed25519 Signatures

Ed25519 digital signatures -- the library's native Schnorr-on-Ed25519 variant
and the standards-compliant RFC 8032 variant. A digital signature proves that
the holder of a secret key authorized a specific message, without revealing the
secret key itself.

**Namespace**: `Crypto::Signature` / `Crypto::RFC8032`
**Headers**: [`signature.h`](signature.h) | [`rfc8032.h`](rfc8032.h)
**Reference**: [RFC 8032 -- Edwards-Curve Digital Signature Algorithm][rfc8032]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Signatures explained with wax seals |
| [Ed25519 (Basic)](#ed25519-basic) | Standard point signing (64 B) |
| [Ed25519 (RFC 8032)](#ed25519-rfc-8032) | Standards-compliant signing (64 B) |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Imagine you're sealing a letter with a **wax seal**. Your seal is unique
to you -- anyone who sees it knows you wrote the letter, and nobody else
can forge your seal without your signet ring.

A **digital signature** is like that wax seal, but with math instead of wax.
Your "signet ring" is your **secret key** (a big number), and the "wax seal"
is a pair of numbers that anyone can check against your **public key**.

```
  BASIC SIGNATURE (Ed25519)
  -------------------------

  Alice has:
    secret key x = (big number, only she knows)
    public key P = x * G  (everyone knows)

  She signs "I'll pay Bob 5 coins":
    1. Pick a random nonce k
    2. Compute R = k * G  (nonce commitment)
    3. Compute challenge e = Hash(message, R, P)
    4. Compute response s = k - e * x

  Signature = (e, s)  -- just 64 bytes

  Verifier checks:
    s * G + e * P  should equal  R
    That is: (k - e*x)*G + e*(x*G) = k*G - e*x*G + e*x*G = k*G = R

  Why it works: only someone who knows x can compute s = k - e*x.
  Nobody else can find s that makes the equation work.
```

---

## Ed25519 (Basic)

**Namespace**: `Crypto::Signature`
**Header**: [`signature.h`](signature.h)

The library's native Ed25519 signature variant. Signs a pre-hashed 32-byte
message digest with a pre-derived secret scalar. This is a straightforward
Schnorr signature on the Ed25519 curve.

```
+------------------------------------+
|         Ed25519 Signature          |
|                                    |
|   Input:  message_digest (32 B)    |
|           secret_key (scalar)      |
|                                    |
|   Output: signature (64 B)         |
|             L: challenge scalar    |
|             R: response scalar     |
|                                    |
|   Verify: check_signature(         |
|     digest, public_key, sig)       |
+------------------------------------+
```

### API

```cpp
// Sign a 32-byte message digest
auto sig = Crypto::Signature::generate_signature(digest, secret_key);

// Verify
bool valid = Crypto::Signature::check_signature(digest, public_key, sig);
```

### Scenario: Alice Signs a Contract

```
FUNCTION sign_contract():
    // Alice is signing a hash of a contract. She has a secret key
    // that she generated earlier, and the contract has been hashed
    // to a 32-byte digest.

    contract = "I agree to sell 100 widgets at $5 each."
    digest = hash_t::sha3(contract, contract.length())
    // digest = "b7e3...91" (32 bytes)

    // Alice's key pair
    [alice_public, alice_secret] = Crypto::generate_keys()

    // Sign
    sig = Crypto::Signature::generate_signature(digest, alice_secret)
    // sig = 64 bytes (challenge + response)

    // Bob verifies (he knows Alice's public key)
    valid = Crypto::Signature::check_signature(digest, alice_public, sig)
    // valid == true

    // If someone changes the contract:
    tampered = hash_t::sha3("I agree to sell 100 widgets at $50 each.", 39)
    valid2 = Crypto::Signature::check_signature(tampered, alice_public, sig)
    // valid2 == false  (signature is bound to the original text)
```

### When to Use

Use this variant when you control both signer and verifier and want a simple,
fast signature. For interoperability with other Ed25519 implementations, use
the RFC 8032 variant below.

---

## Ed25519 (RFC 8032)

**Namespace**: `Crypto::RFC8032`
**Header**: [`rfc8032.h`](rfc8032.h)
**Reference**: [RFC 8032][rfc8032] -- Edwards-Curve Digital Signature Algorithm (EdDSA)

The standards-compliant Ed25519 variant. Accepts arbitrary-length messages
(hashed internally with SHA-512 per the spec). Produces signatures that any
RFC 8032 implementation can verify -- regression-tested against the §7.1
Appendix A test vectors in `src/test.cpp::test_signatures()`.

**Signing semantics: hedged synthetic-nonce.** Rather than RFC 8032 §5.1.6's
pure-deterministic nonce `k = SHA-512(prefix || M) mod L`, this module uses a
*hedged* synthetic nonce `k = H(SHA-512(M) || A || rand)`. Both forms produce
mathematically valid Ed25519 signatures (the §5.1.7 verification equation
`s·G == R + H(R||A||M)·A` holds for any α). Hedged signing is endorsed by
FIPS 186-5 Appendix A and draft-irtf-cfrg-det-sigs-with-noise as a fault-
injection-resistant *improvement* over pure-deterministic signing. The classic
Ed25519 nonce-reuse key-extraction attack cannot fire here because `M_digest`
is in the transcript -- different messages always yield different nonces even
if the RNG is broken.

Trade-off: signatures are NOT byte-reproducible across calls (each invocation
produces a fresh `(R, s)` pair). They are still byte-compatible with every
spec verifier on the wire; they just aren't bit-equal to a libsodium signature
of the same input. If you need byte-reproducibility for offline test-vector
matching, this is not the library for you.

**Key API.** The secret key parameter is a pre-derived `scalar_t`, NOT a raw
32-byte seed. The entire `Crypto::` namespace is scalar-domain by convention.
Callers starting from a 32-byte seed must perform RFC 8032 §5.1.5 expansion
(SHA-512 + clamping + public-key derivation) themselves.

### API

```cpp
// Sign an arbitrary-length message
auto sig = Crypto::RFC8032::generate_signature(
    message_bytes, message_len, secret_key);

// Templated version (works with std::vector, std::string, etc.)
auto sig = Crypto::RFC8032::generate_signature(
    message, secret_key);

// Verify
bool valid = Crypto::RFC8032::check_signature(
    message_bytes, message_len, public_key, sig);

bool valid = Crypto::RFC8032::check_signature(
    message, public_key, sig);
```

### Differences from Basic Variant

| | Basic | RFC 8032 |
|---|-------|---------|
| Message input | 32-byte hash | Arbitrary length |
| Secret key input | Pre-derived scalar | Pre-derived scalar |
| Nonce derivation | Library convention | Hedged synthetic (FIPS 186-5 App. A) |
| Verifier interop | Library only | Any spec-compliant Ed25519 verifier |
| Byte-reproducible | No | No (hedged is intentionally non-reproducible) |

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 3 | Ed25519 basic signatures |

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

### Target `rfc8032`

Source: [`src/fuzz/fuzz_target_rfc8032.cpp`](../../src/fuzz/fuzz_target_rfc8032.cpp)

Entry points exercised:

- `Crypto::RFC8032::generate_signature and check_signature`
- `Crypto::Signature::generate_signature and check_signature`
- `signature_t deserialization (binary + JSON)`

---

## References

| Topic | Link |
|-------|------|
| Ed25519 specification | [RFC 8032 -- Edwards-Curve Digital Signature Algorithm][rfc8032] |

[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032.html
