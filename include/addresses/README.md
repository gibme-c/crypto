# Address Encoding

This module builds on the [Base58](../base58/README.md) module to encode
public keys into checksummed address strings. Supports both single-key
(just a public key) and dual-key (spend key + view key) formats. The
dual-key format is common in privacy systems where a view key allows
read-only access to incoming transactions without spending authority.

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [Overview](#overview) | Address format and structure |
| [API](#api) | Encode and decode functions |
| [Scenario](#scenario-creating-and-sharing-a-wallet-address) | Creating and sharing a wallet address |

---

## How It Works (ELI5)

Imagine you need to give someone your mailing address so they can send you a
package. You could hand them the raw GPS coordinates (47.6062, -122.3321), but
that's error-prone and ugly. Instead, you write "123 Main St, Seattle, WA 98101"
-- a human-friendly format with a built-in sanity check (the ZIP code matches
the city).

Crypto addresses work the same way. Your "GPS coordinates" are one or two raw
32-byte public keys. The address encoder wraps them with a **network prefix**
(which network is this for?) and a **checksum** (did the user type it correctly?),
then converts the whole thing to a compact Base58 string that's safe to copy,
paste, and share.

In privacy systems, addresses often encode **two** keys: a spend key (needed to
authorize transactions) and a view key (needed to scan for incoming payments).
This lets you share view-only access with an auditor without giving them spending
authority.

---

## Overview

**Namespace**: `Crypto::Address::Base58` and `Crypto::Address::CNBase58`
**Header**: [address_encoding.h](address_encoding.h)

```
Single-key address:
+--------+-------------+-----------+
| prefix | public_key  | checksum  |
| varint |  (32 bytes) | (4 bytes) |
+--------+-------------+-----------+
         |                         |
         +--- encode_check() ------+

Dual-key address:
+--------+--------------+--------------+-----------+
| prefix | spend_key    | view_key     | checksum  |
| varint |  (32 bytes)  |  (32 bytes)  | (4 bytes) |
+--------+--------------+--------------+-----------+
         |                                         |
         +---------- encode_check() ---------------+
```

The prefix is a varint-encoded network identifier that distinguishes address
types (mainnet, testnet, subaddress, etc.).

---

## API

```cpp
// Encode with single key
std::string encode(
    const uint64_t &prefix,
    const public_key_t &public_key);

// Encode with dual keys (spend + view)
std::string encode(
    const uint64_t &prefix,
    const public_key_t &public_spend,
    const public_key_t &public_view);

// Decode (returns success, prefix, key1, key2)
std::tuple<bool, uint64_t, public_key_t, public_key_t>
    decode(const std::string &address);
```

Both `Base58` and `CNBase58` sub-namespaces expose the same API. Use
`CNBase58` when deterministic address length matters (most address systems).

### Decoder strictness

After successfully unwrapping the checksum, the decoder reads the network
prefix (varint) and the spend key (32 bytes), then inspects the remaining
unread tail. The only legal layouts are:

- **0 bytes** of tail → single-key address; the returned `key2` is a
  default-constructed (zero) `public_key_t`.
- **`public_key_t::size()` (32) bytes** of tail → dual-key address; `key2`
  is the decoded view key.

Any other tail length (1, 16, 31, 33, 48, 64, ...) is treated as a
malformed address and the decoder fails closed, returning
`{false, 0, {}, {}}`. This avoids ambiguous tails being silently coerced
into a single-key-with-zero-view-key shape, which would mask encoding
errors from callers downstream.

---

## Scenario: Creating and Sharing a Wallet Address

```
FUNCTION create_wallet_address():
    // Alice creates a new wallet and needs a public address she can
    // share with others to receive payments. The address encodes both
    // her spend and view public keys with a network prefix.

    // --- Generate key pairs -----------------------------------------
    [spend_public, spend_secret] = Crypto::generate_keys()
    [view_public, view_secret] = Crypto::generate_keys()
    // spend_public: used to authorize spending (Alice keeps spend_secret)
    // view_public:  used to scan for incoming payments (view_secret can
    //               be shared with an auditor for read-only access)

    // --- Encode the address -----------------------------------------
    // Network prefix 18 = mainnet standard address
    address = Address::CNBase58::encode(18, spend_public, view_public)
    // address = "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeY..."
    // (95 characters, deterministic length)

    // Alice posts this address on her website, sends it via email, etc.

    // --- Bob decodes the address ------------------------------------
    [ok, prefix, key1, key2] = Address::CNBase58::decode(address)
    // ok == true
    // prefix == 18  (mainnet -- Bob's wallet recognizes this)
    // key1 == spend_public
    // key2 == view_public

    // If Bob mistypes the address:
    [ok2, _, _, _] = Address::CNBase58::decode("4AdUndXHHZ6cfufTMvppY6JwXN_TYPO_...")
    // ok2 == false  (checksum catches the typo, Bob's wallet shows an error)

    // --- Why dual-key? ----------------------------------------------
    // Alice can give her view_secret (but NOT spend_secret) to an auditor.
    // The auditor can see all incoming payments to Alice's address,
    // but cannot spend any of them. This is called "view-only access."
```

---

## Dependencies

This module depends on the [Base58](../base58/README.md) module for the
underlying encoding and checksum operations.

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

### Target `addresses`

Source: [`src/fuzz/fuzz_target_addresses.cpp`](../../src/fuzz/fuzz_target_addresses.cpp)

Entry points exercised:

- `Crypto::Address::encode / decode (single-key and dual-key)`
- `Crypto::CryptoNoteAddress::encode / decode (single-key and dual-key)`

---

## References

| Topic | Link |
|-------|------|
| Base58Check encoding | [Bitcoin Wiki: Base58Check encoding][base58wiki] |

[base58wiki]: https://en.bitcoin.it/wiki/Base58Check_encoding
