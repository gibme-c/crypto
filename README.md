# Crypto — Standalone C++17 Cryptographic Primitives

A self-contained cryptographic primitive library built around **Ed25519** elliptic curve operations. Everything you need for key management, signatures, and zero-knowledge proofs in one place — just `#include <crypto.h>` and link against `crypto-static`.

The API leans heavily on operator overloading so that common operations read naturally: `scalar_a * point_b`, `point_a + point_b`, `commitment - pseudo_commitment`. The public-facing types and functions are designed to be approachable — though fair warning, the proof and signature internals get into serious math territory with heavily optimized multi-scalar multiplications, inner product arguments, and Fiat-Shamir transcripts.

## Features

### Hashing

Multiple hash algorithms, all producing a 256-bit `crypto_hash_t`:

- **[SHA-3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)** (Keccak-256) — the workhorse hash used throughout the library
- **SHA-256 / SHA-384 / SHA-512** — standard SHA-2 family
- **[Blake2b](https://www.blake2.net/)** — high-performance alternative
- **[Argon2](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)** — memory-hard password hashing in three flavors:
  - **Argon2d** — GPU/ASIC-resistant (data-dependent access)
  - **Argon2i** — side-channel resistant (data-independent access)
  - **Argon2id** — recommended hybrid of both
- **SHA-3 key stretching** (`sha3_slow`) — iterated hashing with salt mixing for deterministic domain separation

### Core Types

| Type | Description |
|------|-------------|
| `crypto_hash_t` | 256-bit hash value with static methods for all supported algorithms. Converts to `scalar()` or `point()` for use in protocols. |
| `crypto_point_t` | Ed25519 curve point with cached `ge_p3`/`ge_cached` representations for fast repeated arithmetic. Overloads `+`, `-`. |
| `crypto_scalar_t` | Ed25519 scalar (integer mod the group order *l*) with [RFC-8032](https://datatracker.ietf.org/doc/html/rfc8032) clamping. Overloads `+`, `-`, `*`, `/`, including scalar-point multiplication. |
| `crypto_secret_key_t` | RFC-8032 private key — a 32-byte seed that derives a signing scalar (via SHA-512 + clamping) and public key. |
| `crypto_signature_t` | Standard 512-bit Ed25519 signature (commitment point *L* and response scalar *R*). |

**Type aliases** give semantic meaning to points used in different contexts:
- `crypto_public_key_t` — a point representing a public key (*P = sG*)
- `crypto_key_image_t` — a deterministic tag for double-spend detection
- `crypto_pedersen_commitment_t` — a point hiding a value (*C = vH + bG*)
- `crypto_blinding_factor_t` — a scalar used as a commitment blinding factor
- `crypto_derivation_t` — a shared secret point from ECDH key exchange

**Vector types** (`crypto_hash_vector_t`, `crypto_point_vector_t`, `crypto_scalar_vector_t`) provide batch arithmetic — Hadamard products, inner products, batch modular inversion — used extensively in zero-knowledge proof internals.

### Hierarchical Deterministic Keys

Full [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) / [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) / [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) support with all paths fully hardened per [SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) (required for Ed25519 compatibility).

| Type | Role |
|------|------|
| `crypto_entropy_t` | 128-bit (12 words) or 256-bit (24 words) entropy with optional timestamp embedding |
| `crypto_seed_t` | PBKDF2-SHA512 seed derived from entropy + optional passphrase |
| `crypto_hd_key_t` | Derived key pair at any point in a BIP-44 derivation path |

The derivation chain: **entropy** → mnemonic words → **seed** → root key → **child keys** at any path.

Mnemonic encoding supports 10 languages: Chinese (Simplified & Traditional), Czech, English, French, Italian, Japanese, Korean, Portuguese, and Spanish.

### Signatures

| Scheme | Size | Ring | Description |
|--------|------|------|-------------|
| [Ed25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) | 64 B | — | Standard Schnorr signature (generate + check) |
| [RFC-8032 Ed25519](https://datatracker.ietf.org/doc/html/rfc8032) | 64 B | — | Strict RFC-8032 — raw seed input, deterministic nonce, arbitrary-length messages |
| [Borromean](https://github.com/Blockstream/borromean_paper/raw/master/borromean_draft_0.01_34241bb.pdf) | O(*n*) | Yes | Linkable ring signature — prove you own one of *n* keys without revealing which |
| [CLSAG](https://eprint.iacr.org/2019/654.pdf) | O(*n*) | Yes | Compact linkable ring signature with optional Pedersen commitment binding |
| [Triptych](https://eprint.iacr.org/2020/018.pdf) | O(log *n*) | Yes | Logarithmic-size ring signature for much larger anonymity sets |

All three ring signature schemes produce a **key image** — a deterministic, unlinkable tag that detects if the same key signs twice. CLSAG and Triptych optionally support **commitment binding**, tying the signature to confidential transaction amounts.

**Signature timings** (ring size n=4 where applicable):

| Scheme | Sign | Verify |
|--------|---:|---:|
| Ed25519 | ~56 us | ~36 us |
| RFC-8032 Ed25519 | ~59 us | ~46 us |
| Borromean (n=4) | ~530 us | ~230 us |
| CLSAG (n=4) | ~456 us | ~258 us |
| CLSAG w/ commitments (n=4) | ~740 us | ~527 us |
| Triptych (n=4) | ~1.2 ms | ~676 us |

### Zero-Knowledge Proofs

**Pedersen Commitments & RingCT** — hide transaction amounts while preserving verifiable balance:
- Pedersen commitments: *C = vH + bG* (additive homomorphism lets you verify sums without seeing values)
- Amount masking and unmasking via XOR with derived keys
- Pseudo commitment generation for balance proofs

**Range Proofs** — prove a committed value lies in [0, 2^N) without revealing it:

| Scheme | Multi-value | Batch Verify |
|--------|-------------|--------------|
| [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) | Yes | Yes |
| [Bulletproofs+](https://eprint.iacr.org/2020/735.pdf) | Yes | Yes |
| [Bulletproofs++](https://eprint.iacr.org/2022/510.pdf) | Yes | Yes |

All three support variable bit lengths (1–64 bits), multi-value aggregated proving, and cache generator points for fast repeat calls. Proof size grows by only 64 bytes per doubling of M (one additional IPA/WNLA round).

**Aggregated proof scaling** (64-bit range):

| M | Bulletproofs | | | Bulletproofs+ | | | Bulletproofs++ | | |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| | Size | Prove | Verify | Size | Prove | Verify | Size | Prove | Verify |
| 1 | 674 B | ~8.5 ms | ~850 us | 578 B | ~3.6 ms | ~770 us | 516 B | ~3.7 ms | ~470 us |
| 2 | 738 B | ~16 ms | ~1.3 ms | 642 B | ~5.8 ms | ~1.2 ms | 580 B | ~6.3 ms | ~670 us |
| 4 | 802 B | ~31 ms | ~2.0 ms | 706 B | ~9.8 ms | ~2.0 ms | 644 B | ~10.8 ms | ~1.1 ms |
| 8 | 866 B | ~59 ms | ~3.3 ms | 770 B | ~18 ms | ~3.3 ms | 708 B | ~20 ms | ~1.7 ms |
| 16 | 930 B | ~115 ms | ~6.1 ms | 834 B | ~32 ms | ~6.2 ms | 772 B | ~37 ms | ~3.1 ms |

> **Benchmarks measured on:** AMD Ryzen 7 9800X3D, Windows 11, GCC 13.2.0 (MinGW), with x64 SIMD / AVX2 / AVX-512F enabled via `--autotune`.

**Other Proofs:**
- **Merkle trees** — compact membership proofs via binary hash trees
- **Ownership proofs** — prove you control a key or that a specific output belongs to you, without revealing the secret

### Encoding

- **[Base58](https://tools.ietf.org/html/draft-msporny-base58-02)** — human-readable encoding without confusing characters (0, O, I, l)
- **Block-based Base58** — processes input in 8-byte blocks for deterministic output length
- **Address encoding** — checksummed addresses in single-key or dual-key (spend + view) formats, using either Base58 variant
- **[BIP-39 Mnemonics](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)** — entropy ↔ word sequence conversion (SHA-3 checksum) in 10 languages

### Core Utilities

- **Stealth addresses** — one-time addresses via ECDH key derivation, so a sender can pay a recipient without reusing or revealing their public key
- **Key images** — deterministic, unlinkable tags derived from a secret key for double-spend detection
- **Key derivation** — sub-key generation from a shared derivation and output index
- **AES-256 encryption** — symmetric encrypt/decrypt with PBKDF2 key derivation

### Helpers

- **Fiat-Shamir transcripts** — accumulate values and produce challenge scalars for non-interactive zero-knowledge proofs
- **CSPRNG** — cryptographically secure random byte generation from OS entropy
- **Constant-time comparison** — timing side-channel resistant equality checks

### Serialization

All types inherit from `SerializablePod<N>` (via [serialization-cpp](https://github.com/gibme-c/serialization-cpp)), providing:
- Binary serialization and deserialization
- JSON conversion (via [RapidJSON](https://rapidjson.org))
- Hexadecimal string representations
- Pretty printing to screen

## Getting Started

### Requirements

- C++17 compiler (GCC, Clang, or MSVC)
- CMake 3.10+

### Building

```bash
git clone --recursive https://github.com/gibme-c/crypto
cd crypto
mkdir -p build && cd build
cmake .. -DBUILD_TESTS=1
cmake --build . -j$(nproc)
./crypto-test
```

### Using as a Dependency

```bash
git submodule add https://github.com/gibme-c/crypto external/crypto
git submodule update --init --recursive
```

In your `CMakeLists.txt`, add the subdirectory and link against the target:

```cmake
add_subdirectory(external/crypto)
target_link_libraries(your_target PRIVATE crypto-static)
```

Then include the single umbrella header:

```cpp
#include <crypto.h>
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | OFF | Build test and benchmark binaries |
| `BUILD_SHARED` | OFF | Build shared library in addition to static |
| `ENGLISH_ONLY` | OFF | Include only English mnemonic word lists (smaller binary) |
| `DEBUG_PRINT` | OFF | Enable debug print statements |
| `ARCH` | native | Target CPU architecture (`-march` value) |

### Documentation

Full API documentation lives in the header files under `include/`. Every public type, method, and constant has doxygen comments explaining its purpose, parameters, and typical usage.

## License

This library is provided under the **BSD-3-Clause** license. See [LICENSE](LICENSE) for details.

External dependencies (in `external/`) are provided under Public Domain (Unlicense), MIT, and/or BSD licenses from their respective authors. See [CREDITS](CREDITS) or the individual packages for specifics.
