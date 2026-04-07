# Type System

This directory contains every data type in the library -- from 32-byte
cryptographic primitives to variable-length proof structures and batch
operation vectors. All types share a common serialization interface inherited
from the `serializationcpp` library.

All are accessible through `#include <crypto.h>`.

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Building blocks analogy |
| [Inheritance Hierarchy](#inheritance-hierarchy) | Visual type tree |
| [Primitives](#primitives) | hash, point, scalar, secret key, entropy |
| [HD Keys](#hierarchical-deterministic-keys) | seed, hd_key |
| [Ed25519 Vectors](#ed25519-vectors) | hash_vector, point_vector, scalar_vector |
| [Signatures](#signature-types) | signature, borromean, CLSAG, MLSAG, triptych, adapter |
| [Proofs](#proof-types) | bulletproof, BP+, BP++, DLEQ, VRF |
| [Serialization Interface](#serialization-interface) | Common methods all types share |
| [Examples](#examples) | Concrete usage scenarios |

---

## How It Works (ELI5)

Think of the type system like a set of **LEGO bricks** for building
cryptographic constructions. Every brick has a standard connector
(the serialization interface), so they all snap together the same way
-- you can convert any brick to bytes, to hex strings, to JSON, and back.

```
       THE LEGO BRICKS
  ┌──────────────────────────────────────────────────┐
  │                                                  │
  │  SMALL BRICKS (32 bytes each -- fixed size)      │
  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐     │
  │  │  hash  │ │ point  │ │ scalar │ │ secret │     │
  │  │ SHA-3  │ │ curve  │ │ number │ │  key   │     │
  │  │ digest │ │  pt    │ │ mod l  │ │ seed   │     │
  │  └────────┘ └────────┘ └────────┘ └────────┘     │
  │      All inherit from SerializablePod<32>        │
  │      (fixed-size, fast, stack-allocated)         │
  │                                                  │
  │  MEDIUM BRICKS (fixed size, composed of smalls)  │
  │  ┌────────────────┐ ┌────────────────┐           │
  │  │  signature     │ │  DLEQ proof    │           │
  │  │  64 bytes      │ │  64 bytes      │           │
  │  │ (2 scalars)    │ │ (2 scalars)    │           │
  │  └────────────────┘ └────────────────┘           │
  │                                                  │
  │  BIG BRICKS (variable size -- ring, proof data)  │
  │  ┌────────────────────────────────────────────┐  │
  │  │  CLSAG signature (32 + 32N bytes)          │  │
  │  │  Bulletproof++ (~516 + 64*log2(M) bytes)   │  │
  │  └────────────────────────────────────────────┘  │
  │      All inherit from Serializable               │
  │      (variable-size, heap-allocated vectors)     │
  │                                                  │
  │  BUCKETS (vectors -- batches of small bricks)    │
  │  ┌────────────────────────────────────────────┐  │
  │  │  point_vector:  [P₀, P₁, P₂, ..., Pₙ]       │  │
  │  │  scalar_vector: [s₀, s₁, s₂, ..., sₙ]       │  │
  │  │  + arithmetic: inner products, Hadamard,   │  │
  │  │    batch inversion, MSM                    │  │
  │  └────────────────────────────────────────────┘  │
  │                                                  │
  │  CONNECTORS (every brick has these methods):     │
  │    .serialize()   -> bytes                       │
  │    .to_string()   -> hex                         │
  │    .toJSON()      -> JSON                        │
  │    .hash()        -> hash_t                      │
  │    ==, !=, <<     comparisons & debug output     │
  └──────────────────────────────────────────────────┘
```

The key insight: **points** and **scalars** are the atoms of elliptic curve
cryptography. A scalar is a big number (modulo the curve order). A point is
a position on the curve. Multiplying a scalar by a point gives a new point:
`P = x * G`. This one-way operation (easy to compute forward, impossible to
reverse) is the foundation of every signature, proof, and commitment in the
library.

---

## Inheritance Hierarchy

```
SerializablePod<N> (fixed-size, N bytes)
  |-- hash_t (32 B)
  |-- point_t (32 B)
  |     |-- public_key_t (alias)
  |     |-- derivation_t (alias)
  |     |-- key_image_t (alias)
  |     +-- pedersen_commitment_t (alias)
  |-- scalar_t (32 B)
  |     +-- blinding_factor_t (alias)
  |-- secret_key_t (32 B)
  +-- entropy_t (32 B)

SerializableVector<T>
  |-- hash_vector_t
  |-- point_vector_t
  +-- scalar_vector_t

Serializable (variable-size)
  |-- signature_t (64 B)
  |-- borromean_signature_t
  |-- clsag_signature_t
  |-- mlsag_signature_t
  |-- triptych_signature_t
  |-- adapter_signature_t (128 B)
  |-- dleq_proof_t (64 B)
  |-- bulletproof_t
  |-- bulletproof_plus_t
  |-- bulletproof_pp_t
  |-- vrf_proof_t (96 B)
  +-- vrf_rfc9381_proof_t (80 B)
```

---

## Primitives

These are the building blocks for everything else. All are exactly 32 bytes
and inherit from `SerializablePod<32>`, which provides binary serialization,
hex string conversion, JSON, equality comparison, and hashing.

### hash_t

**Header**: [`hash_t.h`](hash_t.h)
**Size**: 32 bytes

A 256-bit hash value. Wraps multiple hash algorithms as static factory
methods. Think of it as a universal fingerprint machine -- feed in any
data, get out a unique 32-byte tag.

```cpp
// SHA3-256 (primary hash -- used throughout the library)
auto h = hash_t::sha3("hello world", 11);
// h = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"

// Iterated SHA3 for key stretching (n iterations)
auto h = hash_t::sha3_slow("password", 8, 10000);

// SHA-256 (for BIP-39 checksum, interoperability)
auto h = hash_t::sha256("hello world", 11);

// BLAKE2b-256 (fast, used in some protocols)
auto h = hash_t::blake2b("hello world", 11);

// Argon2d/i/id (memory-hard password hashing)
auto h = hash_t::argon2d(data, len, salt, salt_len,
    iterations, memory_kb, threads);
auto h = hash_t::argon2i(data, len, salt, salt_len,
    iterations, memory_kb, threads);
auto h = hash_t::argon2id(data, len, salt, salt_len,
    iterations, memory_kb, threads);

// Convenience template -- input used as its own salt
auto h = hash_t::argon2d(input_vec);                   // 1 iter, 256 KB, 1 thread
auto h = hash_t::argon2i(input_vec, 3, 1024);          // 3 iters, 1024 KB, 1 thread
auto h = hash_t::argon2id(input_vec, 3, 1024, 2);      // 3 iters, 1024 KB, 2 threads

// Convert to cryptographic types
auto s = h.scalar();   // interpret as Ed25519 scalar (reduced mod l)
auto p = h.point();    // hash-to-point (Elligator + cofactor clear)
```

### point_t

**Header**: [`point_t.h`](point_t.h)
**Size**: 32 bytes (compressed Edwards-y encoding)

An Ed25519 curve point. Caches internal `ge_p2` and `ge_p3` representations
on first use for performance. Validates curve membership on construction.

Think of a point as a **position on a map**. You can combine two positions
into a new one (addition), or multiply a position by a secret number to get
a completely different position (scalar multiplication). The critical
property: given the starting position (the base point G) and the ending
position (the public key P), it is computationally infeasible to figure out
what number was used to get there. This is the discrete logarithm problem --
the one-way function that underlies every signature and proof in the library.

```cpp
point_t P, Q;
auto R = P + Q;                // point addition
auto R = P - Q;                // point subtraction
auto R = scalar * P;           // scalar multiplication
auto R = point_t::random();  // random point

const auto &p3 = P.p3();      // access cached ge_p3 (internal representation)
const auto *bytes = P.data();  // raw 32-byte compressed encoding
```

**Type aliases** (these are all `point_t` under the hood; the aliases make
code self-documenting and show how the same 32-byte point is used in
different roles throughout the transaction lifecycle):

- `public_key_t` -- Ed25519 public keys (`P = x * G`). Used as wallet
  addresses (spend/view keys) and as the one-time output keys created by
  stealth address derivation.
- `derivation_t` -- ECDH shared secrets (`D = a * B`). The intermediate
  value in stealth address construction -- the sender and recipient each
  compute the same derivation independently, which is then used to derive
  the one-time output key.
- `key_image_t` -- key images for linkable signatures (`I = x * Hp(P)`).
  A unique, deterministic tag for each output. Published when spending an
  output; the network rejects any transaction that reuses a key image
  (double-spend detection).
- `pedersen_commitment_t` -- Pedersen commitments (`C = y*G + a*H`). Hides
  a transaction amount `a` behind a random blinding factor `y`. Each
  transaction output carries a commitment so amounts stay hidden while
  the network can verify that inputs and outputs balance.

### scalar_t

**Header**: [`scalar_t.h`](scalar_t.h)
**Size**: 32 bytes (little-endian integer mod l)

An Ed25519 scalar (integer modulo the group order l). Supports full
arithmetic and RFC-8032 clamping. Think of a scalar as a **secret number**
that you multiply by curve points to get new curve points.

The group order `l` is approximately 2^252 -- a number so large that
guessing a random scalar is like finding a specific atom in the observable
universe. This is why scalar multiplication is a one-way function.

```cpp
scalar_t a, b;
auto c = a + b;                // modular addition
auto c = a - b;                // modular subtraction
auto c = a * b;                // modular multiplication
auto c = a / b;                // modular division (via inverse)
auto c = a.invert();           // modular multiplicative inverse
auto c = a.pow(n);             // modular exponentiation
auto P = a * point;            // scalar-point multiplication
auto c = scalar_t::random();  // random scalar

bool nz = a.is_nonzero();     // constant-time non-zero check
```

**Type alias**: `blinding_factor_t` -- the random scalar used as the
blinding factor in a Pedersen commitment (`C = y*G + a*H`). The blinding
factor `y` is what makes the commitment hiding -- without it, the amount
`a` could be recovered. When constructing a transaction, the sender
chooses random blinding factors for outputs and then balances the input
blinding factors so the commitment sums cancel.

**Validation macros**:
- `SCALAR_OR_THROW(s)` -- throws if `s` is not a valid reduced scalar
- `SCALAR_NZ_OR_THROW(s)` -- throws if `s` is zero or invalid

**Security note**: `scalar_t` automatically performs secure erasure
in its destructor -- the 32 bytes are overwritten with zeros when the
scalar goes out of scope. You never need to manually erase scalars.

### secret_key_t

**Header**: [`secret_key_t.h`](secret_key_t.h)
**Size**: 32 bytes (RFC-8032 seed)

An RFC-8032 Ed25519 private key. The raw 32 bytes are a seed; the signing
scalar and public key are derived via SHA-512 on first use and cached.

```cpp
auto sk = secret_key_t::random();
auto scalar = sk.scalar();     // derived signing scalar
auto pk = sk.public_key();     // derived public key point
```

The difference between `secret_key_t` and `scalar_t`:
- **`secret_key_t`**: An RFC-8032 seed. The actual signing scalar
  is derived from SHA-512 of this seed, then clamped. Use this for
  standards-compliant Ed25519 (`Crypto::RFC8032` namespace).
- **`scalar_t`**: A raw scalar value used directly. Use this for
  the library's native Schnorr variant (`Crypto::Signature` namespace),
  ring signatures, stealth address derivation, key images, and all
  internal math throughout the library. Most of the library's API
  uses `scalar_t` for secret keys, not `secret_key_t`.

### entropy_t

**Header**: [`entropy_t.h`](entropy_t.h)
**Size**: 32 bytes

BIP-39 entropy for HD key derivation and mnemonic encoding. Can represent
128-bit (16 bytes) or 256-bit (32 bytes) entropy. This is the root
secret from which an entire wallet (unlimited key pairs) can be derived.

```cpp
auto e = entropy_t::random();
auto words = Crypto::Mnemonics::encode(e);         // -> 24 words
auto seed = seed_t(e, "passphrase");        // -> BIP-39 seed
```

---

## Hierarchical Deterministic Keys

These types are intentionally **not serializable** -- they contain derived
key material that should be regenerated from the seed rather than stored.

**ELI5**: Imagine a master key that can be used to stamp out an unlimited
number of child keys, each for a different purpose. The master key is
derived from your 24-word mnemonic phrase. Each child key is derived from
the master via a **derivation path** like `m/44'/0'/0'/0'/5'` -- think of
it as a set of instructions: "start at the master, go down branch 44,
then branch 0, then branch 0, then branch 0, then branch 5."

```
24 words (mnemonic phrase)
    |
    v  decode to entropy
entropy_t (32 bytes)
    |
    v  PBKDF2-HMAC-SHA512("mnemonic" + passphrase)
seed_t (64 bytes)
    |
    v  HMAC-SHA512("ed25519 seed", seed_bytes)
Master Key + Chain Code
    |
    v  path = "m/44'/0'/0'/0'/0'"
hd_key_t  -->  .public_key()  -->  address
          -->  .secret_key()  -->  signing
```

### seed_t

**Header**: [`seed_t.h`](seed_t.h)

BIP-39 seed derived from entropy via PBKDF2-HMAC-SHA512. Root of the HD
key tree.

```cpp
auto seed = seed_t(entropy, "passphrase");
auto master_key = seed.key();          // 32-byte master private key
auto chain_code = seed.chain_code();   // 32-byte master chain code
```

### hd_key_t

**Header**: [`hd_key_t.h`](hd_key_t.h)

A single node in the BIP-32/BIP-44/SLIP-10 key tree. Contains a private
key, public key, and chain code for further derivation. All paths are
fully hardened (Ed25519 requirement per SLIP-10).

```cpp
auto key = seed.generate_child_key("m/44'/0'/0'/0'/0'");
auto pk = key.public_key();
auto sk = key.secret_key();

// Different paths produce different key pairs:
auto key_0 = seed.generate_child_key("m/44'/0'/0'/0'/0'");  // account 0, address 0
auto key_1 = seed.generate_child_key("m/44'/0'/0'/0'/1'");  // account 0, address 1
auto key_2 = seed.generate_child_key("m/44'/0'/1'/0'/0'");  // account 1, address 0
// All derived from the same 24 words -- lose the words, lose everything.
// Keep the words, recover everything.
```

---

## Ed25519 Vectors

Batch operation containers for Ed25519 types. Inherit from
`SerializableVector<T>` which provides serialization, indexing, and
iteration. These add mathematical operations specific to their element type.

**ELI5**: Instead of multiplying points one at a time, vectors let you do
batch operations -- like multiplying a list of scalars by a list of points
in a single call (multi-scalar multiplication / MSM). This is dramatically
faster than doing each multiplication individually, because the algorithm
shares intermediate computations across all the terms.

### point_vector_t

**Header**: [`point_vector_t.h`](point_vector_t.h)

Vector of Ed25519 points with element-wise arithmetic and multi-scalar
multiplication (MSM).

```cpp
point_vector_t P(points);
auto Q = P + other_points;         // element-wise addition
auto R = scalars.inner_product(P); // MSM: sum(s_i * P_i)
auto S = P.slice(0, 16);           // sub-range [0, 16)
```

### scalar_vector_t

**Header**: [`scalar_vector_t.h`](scalar_vector_t.h)

Vector of Ed25519 scalars with Hadamard products, inner products, and batch
inversion.

```cpp
scalar_vector_t a(scalars);
auto b = a + other;                // element-wise addition
auto c = a * other;                // Hadamard product (element-wise multiply)
auto d = a * single_scalar;        // broadcast multiply (every element * scalar)
auto e = a.inner_product(other);   // sum(a_i * b_i) -> single scalar
auto f = a.invert();               // batch Montgomery inversion (1 inversion + 3n mults)
auto g = a.negate();               // element-wise negate
```

### hash_vector_t

**Header**: [`hash_vector_t.h`](hash_vector_t.h)

Vector of hashes for Merkle trees and batch operations.

---

## Signature Types

All signature types inherit from `Serializable` and provide binary/JSON
round-trip encoding, `hash()`, and `operator<<` for debug output.

### signature_t (64 B)

**Header**: [`signature_t.h`](../signatures/signature_t.h)

Basic Ed25519 signature: two 32-byte scalars (L = challenge, R = response).
The simplest signature in the library -- proves "I know the secret key
for this public key."

### borromean_signature_t

**Header**: [`borromean_signature_t.h`](../signatures/borromean_signature_t.h)

Borromean ring signature. Contains a vector of `signature_t` pairs (one
challenge-response pair per ring member). Size: 64N bytes.

### clsag_signature_t

**Header**: [`clsag_signature_t.h`](../signatures/clsag_signature_t.h)

CLSAG ring signature. Contains `challenge`, per-member `scalars`,
`commitment_image`, and `pseudo_commitment`. Size: 32 + 32N bytes.

The most commonly used ring signature -- half the size of MLSAG with
identical security properties.

### mlsag_signature_t

**Header**: [`mlsag_signature_t.h`](../signatures/mlsag_signature_t.h)

MLSAG (multi-layer) ring signature. Contains `challenge`, per-member
`key_scalars` and `commitment_scalars`, key image, and pseudo commitment.
Size: 32 + 64N bytes. Legacy -- superseded by CLSAG.

### triptych_signature_t

**Header**: [`triptych_signature_t.h`](../signatures/triptych_signature_t.h)

Triptych logarithmic-size ring signature. Contains commitment points
(A, B, C, D), auxiliary vectors (X, Y), response scalar matrix (f),
and final response scalars (zA, zC, z). Size: ~352 + 64 log2(N) bytes.

The most size-efficient ring signature for large rings -- a ring of 1024
costs only ~992 bytes versus ~32,800 for CLSAG.

### adapter_signature_t (128 B)

**Header**: [`adapter_signature_t.h`](../signatures/adapter_signature_t.h)

Adapter pre-signature for atomic swaps. Contains `adapted_nonce`,
`s_prime` (partial response), and a `dleq_proof_t`.

---

## Proof Types

### dleq_proof_t (64 B)

**Header**: [`dleq_proof_t.h`](../core/dleq_proof_t.h)

Discrete log equality proof (Chaum-Pedersen): proves `log_G(A) = log_H(B)`.
Two 32-byte scalars: `c` (challenge) and `s` (response).

### bulletproof_t

**Header**: [`bulletproof_t.h`](../proofs/bulletproof_t.h)

Original Bulletproof range proof. Fields: `A`, `S` (vector commitments),
`T1`, `T2` (polynomial coefficients), `taux`, `mu` (blinding responses),
`L`, `R` (IPA folding vectors), `g`, `h`, `t` (final scalars).
Size: ~674 bytes for M=1.

### bulletproof_plus_t

**Header**: [`bulletproof_plus_t.h`](../proofs/bulletproof_plus_t.h)

Bulletproofs+ range proof. Fields: `A` (combined commitment), `A1`, `B`
(weighted inner product auxiliary), `r1`, `s1`, `d1` (response scalars),
`L`, `R` (WIP folding). Size: ~578 bytes for M=1.

### bulletproof_pp_t

**Header**: [`bulletproof_pp_t.h`](../proofs/bulletproof_pp_t.h)

Bulletproofs++ reciprocal-argument range proof. The most compact range
proof in the library. Fields: `C_l`, `C_r`, `C_o`, `C_s` (reciprocal
commitments), `R` (norm commitment), `X`, `W` (WNLA folding rounds),
`l`, `n` (final scalar vectors). Size: ~516 bytes for M=1.

### Size Comparison (M=1 value, N=64 bits)

```
Bulletproofs     ████████████████████████████████████████  674 B
Bulletproofs+    ██████████████████████████████████        578 B
Bulletproofs++   ██████████████████████████████            516 B
```

### vrf_proof_t (96 B)

**Header**: [`vrf_proof_t.h`](../proofs/vrf_proof_t.h)

Native VRF proof (SHA-3 hash-to-curve variant). Fields: `gamma` (VRF output
point, 32 B), `c` (Fiat-Shamir challenge scalar, 32 B), `s` (response
scalar, 32 B).

### vrf_rfc9381_proof_t (80 B)

**Header**: [`vrf_proof_t.h`](../proofs/vrf_proof_t.h)

RFC 9381 VRF proof (ECVRF-EDWARDS25519-SHA512-ELL2). Fields: `gamma` (VRF
output point, 32 B), `c` (truncated 16-byte challenge per the RFC spec),
`s` (response scalar, 32 B). Use this variant for interoperability with
other RFC 9381 implementations.

---

## Serialization Interface

All types provide a consistent interface through their base class:

```
SerializablePod<N>               Serializable
  .data() -> const uint8_t*        .serialize() -> vector<uint8_t>
  .size() -> N (constexpr)         .deserialize(vector<uint8_t>)
  .to_string() -> hex string       .size() -> byte count
  .fromJSON(json)                  .to_string() -> hex string
  .toJSON() -> json                .fromJSON(json) / .toJSON()
  .hash() -> hash_t        .hash() -> hash_t
  operator==, operator!=           operator<<  (debug output)
```

`SerializableVector<T>` adds indexing (`operator[]`), iteration
(`begin()`/`end()`), and container operations (`push_back`, `emplace_back`,
`resize`, etc.).

### JSON Format

Fixed-size types serialize as hex strings:
```json
{ "key": "a1b2c3...64hex..." }
```

Variable-size types serialize as JSON objects with named fields:
```json
{
  "A": "hex...",
  "S": "hex...",
  "T1": "hex...",
  "L": ["hex...", "hex...", "hex..."],
  "R": ["hex...", "hex...", "hex..."]
}
```

### Binary Format

All types use the `Serialization::serializer_t` / `deserializer_t` framework
for compact binary encoding. Fixed-size pods write their raw bytes directly.
Variable-size types write a varint length prefix followed by element data.

---

## Examples

### Scenario: Creating a Commitment and Proving It's Non-Negative

Alice wants to commit to 42 coins and prove the value is in [0, 2^64)
without revealing the amount.

```
FUNCTION commitment_with_range_proof():
    // ─── Step 1: Create the commitment ──────────────────────────
    // A Pedersen commitment hides the amount inside a curve point.
    // C = blinding * G + amount * H
    //
    // 'blinding' is a random scalar that makes C look random.
    // Without knowing 'blinding', nobody can extract 'amount' from C.

    blinding = blinding_factor_t::random()  // 32 random bytes
    C = Crypto::RingCT::generate_pedersen_commitment(blinding, 42)
    // C is a pedersen_commitment_t (32 bytes, a curve point)

    // ─── Step 2: Create a range proof ────────────────────────────
    // The Bulletproofs++ prove proves that 42 is in [0, 2^64).
    // The proof is ~516 bytes and reveals NOTHING about the value.

    proof = Crypto::RangeProofs::BulletproofsPP::prove({42}, {blinding})
    // proof is a bulletproof_pp_t

    // ─── Step 3: Verify ──────────────────────────────────────────
    // Anyone with C and proof can verify the committed value is valid.
    // They learn nothing about the actual amount (42).

    valid = Crypto::RangeProofs::BulletproofsPP::verify({proof}, {C})
    // valid == true

    // ─── Step 4: Serialize for transmission ─────────────────────
    // All types serialize to bytes, hex, and JSON:

    bytes = proof.serialize()           // compact binary (vector<uint8_t>)
    hex   = proof.to_string()           // hex string
    json  = proof.toJSON()              // JSON object

    // Reconstruct on the other side:
    proof2 = bulletproof_pp_t()
    proof2.deserialize(bytes)
    // proof2 == proof
```

### Scenario: Working with Scalar and Point Vectors

```
FUNCTION batch_operations():
    // ─── Create vectors ─────────────────────────────────────────
    // Vectors hold multiple scalars or points for batch operations.

    scalars = scalar_vector_t({s1, s2, s3, s4})  // 4 scalars
    points  = point_vector_t({P1, P2, P3, P4})   // 4 points

    // ─── Multi-scalar multiplication (MSM) ──────────────────────
    // Compute: R = s1*P1 + s2*P2 + s3*P3 + s4*P4
    // This is MUCH faster than doing 4 separate scalar mults and
    // adding the results, because MSM shares intermediate work
    // (Straus for n<=32, Pippenger for n>32).

    R = scalars.inner_product(points)   // single curve point

    // ─── Hadamard product ────────────────────────────────────────
    // Element-wise multiply: [a*c, b*d, ...]
    // Used in Bulletproofs inner-product arguments.

    other = scalar_vector_t({t1, t2, t3, t4})
    hadamard = scalars * other          // [s1*t1, s2*t2, s3*t3, s4*t4]

    // ─── Batch inversion ─────────────────────────────────────────
    // Compute [1/s1, 1/s2, 1/s3, 1/s4] using Montgomery's trick:
    // only 1 field inversion + 3n multiplications instead of n inversions.

    inverses = scalars.invert()         // [s1^-1, s2^-1, s3^-1, s4^-1]
```
