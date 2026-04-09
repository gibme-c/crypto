# Base58 Encoding

This module provides two Base58 encoding variants: standard Bitcoin-style
Base58 and CryptoNote block-based Base58. Both convert raw bytes to
human-readable strings using an alphabet that omits visually ambiguous
characters.

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [Base58](#base58) | Standard Bitcoin-style encoding |
| [CryptoNote Base58](#cryptonote-base58) | Block-based fixed-width encoding |
| [When to Use Which](#when-to-use-cnbase58-vs-base58) | Comparison of the two variants |

---

## How It Works (ELI5)

Imagine you need to write down a very long number -- say, your 32-byte secret
key. In raw hex, that's 64 characters of gibberish like `7f3a...c91b`. Easy to
misread a `0` as an `O`, or an `I` as an `l`. Base58 solves this by encoding
binary data into a shorter alphabet that **deliberately removes confusing
characters** (`0`, `O`, `I`, `l`). The result is a string that's safe to read
aloud, copy by hand, or print on paper without ambiguity.

The optional checksum variants (`encode_check` / `decode_check`) append a short
hash of the data to the end. If you mistype even one character, the checksum
won't match and the decode fails -- catching the error before you accidentally
send coins to the wrong address.

---

## Base58

**Namespace**: `Crypto::Base58`
**Header**: [base58.h](base58.h)

Standard Bitcoin-style Base58 encoding. The alphabet omits visually ambiguous
characters (`0`, `O`, `I`, `l`) to prevent transcription errors when humans
copy addresses by hand.

```
Alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
          (58 characters -- no 0, O, I, or l)
```

```
 Raw bytes                        Base58 string
+-----------+                    +----------------+
| 0x00 0x01 | -- big-endian -->  | "12"           |
| 0x02 0x03 |    base-256 to     | (variable      |
| ...       |    base-58         |  length)       |
+-----------+                    +----------------+

 With checksum:
+-----------+-----------+        +----------------+
| payload   | SHA3[:4]  | -----> | encoded string |
+-----------+-----------+        +----------------+
```

Leading zero bytes are preserved as `1` characters in the output. The checksum
variant appends 4 bytes of SHA-3 hash before encoding, and verifies them on
decode.

### API

```cpp
// Basic encode: converts raw bytes to a Base58 string
std::string encode(std::vector<uint8_t> input);

// Basic decode: returns (success, reader) where the reader provides
// the decoded bytes via reader.bytes() or reader.pod<T>()
std::tuple<bool, Serialization::deserializer_t> decode(const std::string &input);

// With 4-byte SHA-3 checksum appended before encoding (catches typos on decode)
std::string encode_check(const std::vector<uint8_t> &input);
std::tuple<bool, Serialization::deserializer_t> decode_check(const std::string &input);
```

### Scenario: Encoding a Hash for Display

```
FUNCTION encode_hash():
    // Alice computed a SHA3 hash and wants to display it as a
    // compact, unambiguous string (shorter than hex).

    data = "Hello, world!"
    hash_bytes = sha3(data)     // 32 bytes

    // Hex: 64 characters, easy to confuse 0/O and 1/l
    hex = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"

    // Base58: 44 characters, no ambiguous characters
    encoded = Base58::encode(hash_bytes)
    // encoded = "7YWHMfk9JZe5j8TqMy4GjPcRnBdN2Z5RQdMvx5iCwvoo"

    // With checksum (catches typos):
    checked = Base58::encode_check(hash_bytes)
    // checked = "2DfPNyL7iopmxcAw3..."  (48 characters)

    // Decode:
    [ok, reader] = Base58::decode(encoded)
    // ok == true, reader contains the original 32 bytes

    // If someone mistypes a character:
    [ok2, reader2] = Base58::decode_check("2DfPNyL7iopmxcAw3..X")
    // ok2 == false  (checksum mismatch!)
```

---

## CryptoNote Base58

**Namespace**: `Crypto::CNBase58`
**Header**: [cn_base58.h](cn_base58.h)

Block-based Base58 that processes data in fixed 8-byte blocks, each producing
exactly 11 Base58 characters. This gives **deterministic output length** --
you can compute the encoded size from the input size alone, which is essential
for address encoding where fixed-width fields must be parsed without
delimiters.

```
Input bytes   Blocks            Output characters
+---------+   +---------+       +-------------+
| 8 bytes | = | block 0 | ----> | 11 chars    |
+---------+   +---------+       +-------------+
| 8 bytes | = | block 1 | ----> | 11 chars    |
+---------+   +---------+       +-------------+
| N bytes | = | partial | ----> | 2-10 chars  |
+---------+   +---------+       +-------------+
                                  (from lookup table)

Partial block sizes: 1B->2, 2B->3, 3B->5, 4B->6, 5B->7, 6B->9, 7B->10
```

The API is identical to standard Base58 (`encode`, `decode`, `encode_check`,
`decode_check`).

### API

```cpp
std::string encode(const std::vector<uint8_t> &input);
std::tuple<bool, Serialization::deserializer_t> decode(const std::string &input);

std::string encode_check(const std::vector<uint8_t> &input);
std::tuple<bool, Serialization::deserializer_t> decode_check(const std::string &input);
```

---

## When to Use CNBase58 vs Base58

| | Base58 | CNBase58 |
|---|--------|----------|
| Output length | Variable (depends on leading zeros) | Deterministic (computable from input size) |
| Parsing | Need a delimiter or length prefix | Can split by fixed offsets |
| Use case | General encoding | Address encoding, fixed-format protocols |

---

## Checksum

Both variants use the same checksum scheme:

| Module | Checksum Algorithm | Size | Error Detection |
|--------|--------------------|------|-----------------|
| Base58 | SHA-3 | 4 bytes | Accidental corruption |
| CNBase58 | SHA-3 | 4 bytes | Accidental corruption |

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

### Target `base58`

Source: [`src/fuzz/fuzz_target_base58.cpp`](../../src/fuzz/fuzz_target_base58.cpp)

Entry points exercised:

- `Crypto::Base58::encode / decode (raw and check variants)`
- `Crypto::CryptoNoteBase58::encode / decode (raw and check variants)`

---

## References

| Topic | Link |
|-------|------|
| Base58Check encoding | [Bitcoin Wiki: Base58Check encoding][base58wiki] |

[base58wiki]: https://en.bitcoin.it/wiki/Base58Check_encoding
