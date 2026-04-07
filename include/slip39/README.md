# SLIP-39 Shamir Secret Sharing

This module splits entropy into N mnemonic shares using Shamir's Secret
Sharing. Any T (threshold) shares can reconstruct the original entropy, but
T-1 shares reveal nothing. Optional passphrase protection adds a second
authentication factor via PBKDF2-keyed Feistel cipher.

**Namespace**: `Crypto::Mnemonics::Shamir`
**Header**: [slip39.h](slip39.h)
**Reference**: [SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes][slip39]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Treasure map split among friends |
| [Overview](#overview) | How SLIP-39 secret sharing works |
| [Share Format](#share-format) | Header, data, and checksum layout |
| [API](#api) | Split, combine, and validate functions |
| [Scenario](#scenario-distributing-wallet-backup-to-family-members) | Distributing wallet backup to family members |

---

## How It Works (ELI5)

Imagine you have a treasure map and you want to give pieces to 5 friends. You
don't want any single friend to find the treasure alone (what if they're
dishonest?). But you also don't want to require all 5 (what if someone loses
their piece?). SLIP-39 creates 5 "magic" pieces where **any 3** together
reveal the full map, but **any 2** reveal absolutely nothing -- not even a
partial hint.

The math behind this is called **Shamir's Secret Sharing**: it encodes the
secret as the constant term of a polynomial, then hands out evaluations of
that polynomial at different points. Any T points reconstruct the polynomial
(and recover the secret) via interpolation, but T-1 points leave infinitely
many possible polynomials -- so the secret stays perfectly hidden.

Each share is a sequence of words from a SLIP-39-specific 1024-word list, just
like a BIP-39 mnemonic. You can write each share on paper, store them in
different locations, give them to family members, lock them in safe deposit
boxes -- whatever fits your threat model.

---

## Overview

SLIP-39 splits a single secret into N word-based shares such that any T of
them can rebuild the original, while fewer than T shares reveal nothing.

```
Original entropy (256 bits)
            |
            v  Shamir SSS over GF(256)
    +-------+-------+-------+-------+-------+
    |       |       |       |       |       |
 Share 1 Share 2 Share 3 Share 4 Share 5    (N=5 shares)
 33 words 33 words 33 words 33 words 33 words

    Any T=3 shares reconstruct the entropy:
    Share 1 + Share 3 + Share 5  -->  Lagrange interpolation  -->  entropy

    Any 2 shares reveal NOTHING:
    Share 1 + Share 3  -->  ???  (mathematically impossible to recover)
```

SLIP-39 uses its own separate 1024-word English word list (10 bits per word)
defined in [slip39_english.h](slip39_english.h).

---

## Share Format

Each share encodes a 40-bit header (identifier, group metadata, member
index, threshold) plus the share data plus a 3-word RS1024 checksum:

```
+------------+-----------+-----------+
| header     | share     | RS1024    |
| (40 bits)  | data      | checksum  |
|            | (var)     | (3 words) |
+------------+-----------+-----------+
```

---

## API

```cpp
// Split entropy into N shares with threshold T
std::vector<std::vector<std::string>> split(
    const entropy_t &entropy,
    size_t threshold,          // T (minimum shares to reconstruct)
    size_t total_shares,       // N (total shares generated)
    const std::string &passphrase = "",
    uint8_t iteration_exponent = 0,
    bool extendable = true,
    size_t entropy_bits = 0);  // 0 = defer to entropy_t::bits(); 128/256 to override

// Combine T+ shares to recover entropy
entropy_t combine(
    const std::vector<std::vector<std::string>> &shares,
    const std::string &passphrase = "");

// Validate a single share's checksum
bool validate_share(const std::vector<std::string> &words);

// Derive a 64-byte seed via PBKDF2-HMAC-SHA256
std::vector<unsigned char> derive_seed(
    const entropy_t &entropy,
    const std::string &passphrase = "",
    bool extendable = true,
    size_t entropy_bits = 0);  // 0 = defer to entropy_t::bits(); 128/256 to override
```

### Entropy length

SLIP-39 operates on either 128-bit or 256-bit master secrets. The library
determines which by deferring to `entropy_t::bits()`, which is the canonical
accessor for the `entropy_t` storage convention: a 32-byte POD where 128-bit
entropy lives in the lower 16 bytes with the upper 16 zeroed. Both `split()`
and `derive_seed()` accept an optional `entropy_bits` override:

- `entropy_bits = 0` (default) -- length is inferred via `entropy.bits()` per
  the library convention. This is what you want in nearly all cases.
- `entropy_bits = 128` or `256` -- explicit override; honored verbatim without
  cross-checking the entropy_t. Use this only when you hold a 32-byte value
  constructed outside the library convention (e.g., a genuinely 256-bit secret
  whose upper half is zero by chance, or entropy built from an external
  source) and you know the full 32 bytes are meaningful.
- Any other non-zero value throws `std::invalid_argument`.

Both `split()` and `derive_seed()` defer to `entropy_t::bits()` for length
inference and expose the symmetric `entropy_bits` override. The single source
of truth for the 16-vs-32-byte convention lives at
`src/types/entropy_t.cpp::is_128_bit()`.

**HMAC nuance for derive_seed()**: when a caller passes a degenerate entropy
whose upper 16 bytes are all zero, the `entropy_bits=128` and `entropy_bits=256`
paths produce the **same** 64-byte seed. This is a correct cryptographic
consequence of HMAC-SHA256 zero-padding PBKDF2 keys to its 64-byte block size
-- feeding HMAC the 16 bytes `[x]` is equivalent to feeding it the 32 bytes
`[x, 0...]`. The override is still observable for **non-degenerate** 256-bit
entropies: on a genuinely random 256-bit secret, `entropy_bits=128` truncates
to the lower 16 bytes and produces a different seed than the default path.
We deliberately do **not** domain-separate via the salt (e.g., by appending
the length), because the SLIP-39 spec fixes the salt as `"shamir_extendable"`
or `"shamir"` (+passphrase), and any deviation would break interop with
reference implementations.

---

## Scenario: Distributing Wallet Backup to Family Members

```
FUNCTION family_backup():
    // Alice wants to back up her wallet so that:
    //   - If she's incapacitated, her family can recover the funds
    //   - No single family member can access the funds alone
    //   - The backup survives even if 2 of 5 shares are lost

    entropy = entropy_t::random()

    // Split into 5 shares, any 3 can reconstruct
    shares = Shamir::split(entropy, 3, 5)
    // shares[0] = ["academic", "acid", "acne", "acquire", "acrobat",
    //              "action", "active", "actress", "adapt", "adequate",
    //              "adjust", "admit", "adult", "advance", "advocate",
    //              "afraid", "again", "agree", "airline", "airport",
    //              "ajar", "alarm", "album", "alcohol", "alien",
    //              "alive", "alpha", "already", "alto", "amazing",
    //              "amount", "amuse", "ancient"]
    //  (33 words per share for 256-bit entropy)

    // Alice distributes:
    //   Share 1 -> safe deposit box at Bank A
    //   Share 2 -> her brother Dave
    //   Share 3 -> her sister Eve
    //   Share 4 -> her lawyer's office
    //   Share 5 -> fireproof safe at home

    // --- Recovery scenario 1: Alice loses her phone -----------------
    // Alice retrieves shares 1 (bank) and 5 (home safe),
    // and asks Eve for share 3:

    recovered = Shamir::combine({shares[0], shares[2], shares[4]})
    // recovered == entropy  (Alice rebuilds her wallet!)

    // --- Recovery scenario 2: Alice is incapacitated ----------------
    // Dave (share 2), Eve (share 3), and the lawyer (share 4)
    // combine their shares:

    recovered = Shamir::combine({shares[1], shares[2], shares[3]})
    // recovered == entropy  (family recovers the funds!)

    // --- Attack scenario: Dave and Eve try to steal -----------------
    // Dave has share 2, Eve has share 3. That's only 2 of 3 needed.
    // They cannot recover the entropy. The math guarantees that
    // 2 shares reveal exactly ZERO information about the secret.

    // --- Validate a single share ------------------------------------
    // Each share has its own RS1024 checksum (3 words at the end).
    // You can verify a share is intact without needing other shares:
    valid = Shamir::validate_share(shares[1])
    // valid == true (checksum matches, no transcription errors)
```

---

## Checksum

| Module | Checksum Algorithm | Size | Error Detection |
|--------|--------------------|------|-----------------|
| SLIP-39 | RS1024 | 3 words (30 bits) | Corrects up to 2 errors |

---

## Related Modules

- [BIP-39 Mnemonics](../mnemonics/README.md) -- entropy to word phrases
  (12/24 words) without secret sharing

---

## References

| Topic | Link |
|-------|------|
| SLIP-39 Shamir sharing | [SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes][slip39] |
| Shamir's Secret Sharing | [Shamir, 1979: How to Share a Secret][shamir-paper] |
| Reed-Solomon error correction | [RS1024 checksum specification (SLIP-39 Appendix A)][rs1024] |

[slip39]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
[shamir-paper]: https://dl.acm.org/doi/10.1145/359168.359176
[rs1024]: https://github.com/satoshilabs/slips/blob/master/slip-0039.md#appendix-a-rs1024
