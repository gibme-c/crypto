# Helpers & Utilities

This directory contains internal support modules used throughout the
cryptographic library. These are not proof systems or signature schemes --
they are the building blocks those systems rely on: transcripts for
Fiat-Shamir challenges, cryptographic randomness, HD key derivation,
constant-time comparison, and formatting utilities.

All are accessible through `#include <crypto.h>`.

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | What helpers do and why they matter |
| [Scalar Transcript](#scalar-transcript) | Fiat-Shamir challenges for Ed25519 proofs |
| [HD Keys](#hd-keys) | BIP-32/BIP-44 hierarchical key derivation |
| [Constant-Time Compare](#constant-time-compare) | Timing-safe byte comparison |
| [Gray Code Generator](#gray-code-generator) | Gray code sequences for Triptych |
| [Wide Reduction](#wide-reduction) | SHA-512 digest to Ed25519 scalar reduction |
| [Key Dedup & Sort](#key-dedup--sort) | Canonical key ordering for ring signatures |
| [String Helper](#string-helper) | Padded formatting for debug output |
| [Debug Helper](#debug-helper) | Conditional debug printing and exception macros |
| [Module Relationships](#module-relationships) | How helpers connect to the rest of the library |

---

## How It Works (ELI5)

If the signature and proof modules are the **main actors** in a play,
the helpers are the **stage crew** -- they set up the lights, hand out
props, and make sure the curtain opens on cue. Nobody in the audience
sees them, but the show can't run without them.

```
  THE STAGE CREW
  ──────────────

  ┌──────────────────────────────────────────────────────────┐
  │                                                          │
  │  TRANSCRIPTS  ("The script coordinator")                 │
  │    Every proof needs a deterministic challenge number.   │
  │    The transcript records what the prover said, hashes   │
  │    it, and produces the same challenge for both prover   │
  │    and verifier. Without this, proofs would need a       │
  │    trusted coin-flipper (interactive protocols).         │
  │                                                          │
  │  HD KEYS  ("The key factory")                            │
  │    Takes a single master seed and stamps out unlimited   │
  │    child keys, each at a unique "address" in a tree.     │
  │    Used to derive spend keys, view keys, subaddresses.   │
  │                                                          │
  │  CONSTANT-TIME  ("The silent guard")                     │
  │    Compares secret values without leaking timing info.   │
  │    A normal == check returns faster for mismatches at    │
  │    early bytes. An attacker watching timing could learn  │
  │    the first few bytes of a secret. Constant-time        │
  │    comparison always takes the same time, win or lose.   │
  │                                                          │
  │  GRAY CODE  ("The set-change optimizer")                 │
  │    Produces sequences where consecutive values differ    │
  │    in exactly one position. Triptych uses this to update │
  │    one matrix column per step instead of rebuilding the  │
  │    entire matrix -- turning O(N²) work into O(N).        │
  │                                                          │
  │  WIDE REDUCTION  ("The number shrinker")                 │
  │    Takes a 512-bit SHA-512 hash and squeezes it down     │
  │    to an Ed25519 scalar without bias. Needed for RFC     │
  │    8032 signatures where the challenge is a full         │
  │    64-byte hash.                                         │
  └──────────────────────────────────────────────────────────┘
```

---

## Scalar Transcript

**Header**: [`scalar_transcript_t.h`](scalar_transcript_t.h)

The Fiat-Shamir transcript for all Ed25519-based proof systems (Bulletproofs,
BP+, BP++, CLSAG, Triptych, DLEQ, VRF). Accumulates commitments and
public values into a running SHA-3 hash, then squeezes deterministic
challenge scalars. Both prover and verifier build the same transcript
independently, making interactive proofs non-interactive.

**ELI5**: Imagine a game where Alice (the prover) and Bob (the verifier)
take turns. Alice says something, then Bob flips a coin, then Alice responds.
The coin flip must be random and fair. In person, Bob can flip a real coin.
Over the internet, they use a transcript instead: Alice writes down what she
said, both sides hash it together, and the hash IS the coin flip. Because
SHA-3 is deterministic, they get the same "flip" without trusting each other.

```
Prover                              Verifier
  |                                    |
  |  construct transcript(seed)        |  construct transcript(seed)
  |  update(commitment_A)              |  update(commitment_A)
  |  update(commitment_B)              |  update(commitment_B)
  |  x = challenge()                   |  x = challenge()
  |       |                            |       |
  |       +--- same x (deterministic)  +-------+
  |                                    |
  |  update(response)                  |  update(response)
  |  y = challenge()                   |  y = challenge()
  v        +--- same y ----------------+       v
```

### API

```cpp
struct scalar_transcript_t
{
    // Construct with domain-specific seed (1-4 values)
    template<typename T> explicit scalar_transcript_t(const T &seed);
    template<typename T, typename U>
        scalar_transcript_t(const T &seed, const U &seed2);
    template<typename T, typename U, typename V>
        scalar_transcript_t(const T &seed, const U &seed2, const V &seed3);
    template<typename T, typename U, typename V, typename W>
        scalar_transcript_t(const T &seed, const U &seed2,
                            const V &seed3, const W &seed4);

    // Append values to the transcript (1-4 values, or a vector)
    template<typename T> void update(const T &input);
    template<typename T, typename U>
        void update(const T &input, const U &input2);
    template<typename T, typename U, typename V>
        void update(const T &input, const U &input2, const V &input3);
    template<typename T, typename U, typename V, typename W>
        void update(const T &input, const U &input2,
                    const V &input3, const W &input4);
    template<typename T> void update(const std::vector<T> &input);

    // Squeeze a challenge scalar
    scalar_t challenge();

    // Reset to initial state
    void reset();
};
```

### Scenario: Building a Schnorr Proof Transcript

```
FUNCTION schnorr_proof_transcript():
    // Alice wants to prove she knows x such that P = x * G.
    // She uses a Fiat-Shamir transcript to make the proof non-interactive.

    // ─── Prover (Alice) ─────────────────────────────────────────
    // 1. Seed the transcript with the domain constant and public data.
    //    This ensures this proof can't be replayed in a different context.
    transcript = scalar_transcript_t(SIGNATURE_DOMAIN_0, message, P)

    // 2. Pick a random nonce and commit to it.
    k = random_scalar()
    R = k * G
    transcript.update(R)

    // 3. Squeeze the challenge. This is the "coin flip" -- deterministic
    //    from everything we've fed into the transcript so far.
    e = transcript.challenge()
    // e = SHA3(SIGNATURE_DOMAIN_0 || message || P || R), reduced mod l

    // 4. Compute the response.
    s = k - e * x

    // Proof = (R, s)   [or equivalently (e, s)]

    // ─── Verifier (Bob) ─────────────────────────────────────────
    // Bob builds the SAME transcript from public data:
    transcript2 = scalar_transcript_t(SIGNATURE_DOMAIN_0, message, P)
    transcript2.update(R)     // R is in the proof
    e2 = transcript2.challenge()
    // e2 == e  (same inputs, same hash, same challenge!)

    // Bob checks: s*G + e*P should equal R
    // s*G + e*P = (k - e*x)*G + e*(x*G) = k*G = R  ✓
```

---

## HD Keys

**Header**: [`hd_keys.h`](hd_keys.h)

BIP-32 / BIP-44 / SLIP-10 hierarchical deterministic key derivation helpers.
Derives child keys from a master seed using HMAC-SHA512, with all paths
fully hardened (as required by SLIP-10 for Ed25519).

**ELI5**: Think of a master key as a rubber stamp that can produce infinitely
many unique child stamps. Each child stamp is derived by a "recipe"
(the path), and the same master key + recipe always produces the same child.
The recipe uses slashes and numbers: `m/44'/0'/0'/0'/5'` means "start at
master, go through these 5 derivation steps." The `'` means "hardened" --
even if someone knows the child key, they can't figure out the parent.

```
Master Seed (entropy -> PBKDF2)
       |
       v  HMAC-SHA512("ed25519 seed", seed)
  Master Key + Chain Code
       |
       v  path = "m/44'/0'/0'/0'/0'"
       |
  +----+----+----+----+----+
  | 44'| 0' | 0' | 0' | 0' |  (each level: HMAC-SHA512)
  +----+----+----+----+----+
       |
       v
  Child Key + Chain Code
```

### API

```cpp
// Core HMAC-SHA512
std::vector<unsigned char> calculate_hmac_sha512(
    const void *key, size_t key_length,
    const void *message, size_t message_length);

// Derive child key from parent along a path
std::tuple<hash_t, hash_t> generate_hd_child_key(
    const hash_t &parent_key,
    const hash_t &chain_code,
    const std::string &path);

// Build BIP-44 paths (all hardened)
std::string make_bip32_path(
    size_t purpose = 44,
    size_t coin_type = 0,
    size_t account = 0,
    size_t change = 0,
    size_t address_index = 0);
// Returns: "m/44'/0'/0'/0'/0'"
```

### Scenario: Deriving Multiple Addresses from One Seed

```
FUNCTION derive_addresses():
    // Alice has one 24-word mnemonic. She wants to derive multiple
    // independent key pairs for different purposes -- all from the
    // same master seed.

    entropy = Mnemonics::decode(alice_24_words)
    seed = seed_t(entropy, "")
    master_key   = seed.key()
    master_chain = seed.chain_code()

    // ─── Main spending key ──────────────────────────────────────
    path_0 = make_bip32_path(44, 128, 0, 0, 0)    // "m/44'/128'/0'/0'/0'"
    [key_0, chain_0] = generate_hd_child_key(master_key, master_chain, path_0)
    // key_0 is Alice's primary spending key

    // ─── Second address ─────────────────────────────────────────
    path_1 = make_bip32_path(44, 128, 0, 0, 1)    // "m/44'/128'/0'/0'/1'"
    [key_1, chain_1] = generate_hd_child_key(master_key, master_chain, path_1)
    // key_1 is Alice's second address -- completely independent of key_0

    // ─── View key (different "change" branch) ───────────────────
    // The view key is derived from a different branch of the tree (change=1
    // instead of change=0). It lets Alice (or an auditor she trusts) scan
    // the network for incoming payments addressed to her stealth addresses,
    // without granting the ability to spend those payments.
    path_v = make_bip32_path(44, 128, 0, 1, 0)    // "m/44'/128'/0'/1'/0'"
    [view_key, view_chain] = generate_hd_child_key(master_key, master_chain, path_v)

    // All three keys are deterministic: same 24 words always produce
    // the same keys. Different paths = different keys. Same path = same key.
```

---

## Constant-Time Compare

**Header**: [`constant_time.h`](constant_time.h)

Timing-safe byte comparison for secret data. Always reads all bytes
regardless of where a mismatch occurs, preventing timing side-channel
attacks when comparing MACs, keys, or password hashes.

**ELI5**: A normal `==` check stops at the first mismatch. If an attacker
measures the response time, they can figure out how many leading bytes
matched. By trying all 256 values for byte 1, they find the match (shorter
response time), then move to byte 2, and so on -- cracking the secret one
byte at a time. Constant-time comparison always checks ALL bytes, making
every comparison take the same time regardless of where the mismatch is.

```
Normal comparison (DANGEROUS for secrets):
  Secret:  a3 f2 c9 b7 ...
  Guess 1: 00 xx xx xx ...  -> fails at byte 0 (fast)
  Guess 2: a3 00 xx xx ...  -> fails at byte 1 (slightly slower)
  Guess 3: a3 f2 00 xx ...  -> fails at byte 2 (even slower)
  ^ attacker learns bytes one at a time from timing!

Constant-time comparison (SAFE for secrets):
  Always reads all N bytes, accumulates XOR differences.
  Same time whether 0 bytes match or all bytes match.
  Attacker learns nothing from timing.
```

### API

```cpp
static inline bool constant_time_equals(
    const void *a, const void *b, size_t len);
```

Accumulates XOR differences across all `len` bytes and returns true only
if the accumulator is zero. Does not reveal *where* buffers differ.

---

## Gray Code Generator

**Header**: [`gray_code_generator_t.h`](gray_code_generator_t.h)

Generates generalized Gray code sequences where consecutive values differ
in exactly one digit position. Used by Triptych ring signatures for
efficient matrix traversal -- each step requires only one column update
instead of recomputing the entire matrix.

**ELI5**: Normal counting goes 00, 01, 10, 11 -- between 01 and 10, TWO
bits changed. Gray code goes 00, 01, 11, 10 -- only ONE bit changes each
step. Triptych exploits this: when processing ring members in Gray code
order, only one column of the commitment matrix changes per step, reducing
the work from O(N * m) to O(N + m) per step.

```
Standard Gray code (N=2, K=3):
  000 -> 001 -> 011 -> 010 -> 110 -> 111 -> 101 -> 100
              ^           ^
              |           |
         1 bit changed  1 bit changed
```

### API

```cpp
struct gray_code_generator_t
{
    gray_code_generator_t(size_t N, size_t K, size_t v = -1);

    std::vector<int> operator[](int i) const;  // changed positions at step i
    size_t size() const;                        // sequence length (N^K)
    std::vector<std::vector<int>> values() const;
    std::vector<int> v_value() const;
};
```

---

## Wide Reduction

**Header**: [`wide_reduction.h`](wide_reduction.h)

Reduces a 512-bit SHA-512 digest into an Ed25519 scalar without modular bias.
Splits the 64-byte input into three limbs and reconstructs as
`a + b * 2^168 + c * 2^336`, then reduces mod the group order *l*. Used by
RFC 8032 signature generation to compute the challenge scalar from the
SHA-512 hash of (R || public_key || message).

**ELI5**: SHA-512 produces a 64-byte number, but Ed25519 scalars are only
32 bytes (and must be less than a specific prime). You can't just chop the
hash in half -- that would introduce bias. Instead, wide reduction treats the
full 64 bytes as a very large number and reduces it modulo the group order,
like dividing by *l* and keeping the remainder. The three-limb split avoids
overflow during the computation.

### API

```cpp
// Reduce a 64-byte SHA-512 digest to an unbiased Ed25519 scalar.
scalar_t reduce_wide_hash(const unsigned char input[64]);

// Load a sub-range of a 64-byte buffer into a zero-padded scalar.
scalar_t load_partial_scalar(const unsigned char input[64], size_t start, size_t end);
```

### Use Cases

- **RFC 8032 signatures** -- computing the challenge
  `e = SHA-512(R || public_key || message)` as a scalar
- Any protocol requiring unbiased reduction of SHA-512 output to an Ed25519
  scalar

---

## Key Dedup & Sort

**Header**: [`dedupe_and_sort_keys.h`](dedupe_and_sort_keys.h)

Removes duplicate keys and sorts the remainder by raw byte value. Used in
ring signature construction to establish a canonical, deterministic key
ordering that both signer and verifier agree on.

**ELI5**: When building a ring signature, duplicate public keys would break
the security guarantees (an attacker could fill a ring with copies of the
same key). This utility sorts keys by raw bytes and removes duplicates,
giving a canonical unique list. The ring signature functions use it
internally to reject rings containing duplicates -- you do not need to call
it yourself before signing or verifying.

### API

```cpp
template<typename T>
std::vector<T> dedupe_and_sort_keys(const std::vector<T> &keys);
```

Template parameter `T` must expose `.data()` and `.size()` (satisfied by
all `SerializablePod<N>` types like `public_key_t`). Ordering uses
`memcmp` for platform-independent determinism.

---

## String Helper

**Header**: [`string_helper.h`](string_helper.h)

Convenience macros for creating fixed-width, padded string representations.
Used by the `operator<<` overloads on all proof and signature types for
aligned debug/benchmark output.

### Macros

```cpp
// Pad a named field:  "field_name    : value"
PAD_NAMED(obj, "field_name", width)

// Pad an arbitrary string to width
PAD_STR("label", width)

// Pad using the variable name as the label
PAD_VALUE(obj, width)
```

These delegate to `Serialization::str_pad()` from the serialization library
and call `.to_string()` on the object for the value portion.

---

## Debug Helper

**Header**: [`debug_helper.h`](debug_helper.h)

Conditional debug printing (gated behind `-DDEBUG_PRINT`) and exception
augmentation macros that capture source location.

### Macros

```cpp
PRINTF(value)                 // prints value with file:line (no-op without DEBUG_PRINT)
RETHROW(type, message, err)   // re-throw with source location
SMART_CATCH(type, message)    // catch(...) + RETHROW
```

### Debug Printers

```cpp
namespace Debug {
    void debug_print(const std::string &name, bool value);

    template<typename T>
    void debug_printer(const std::string &name, const T &value);

    template<typename T>
    void debug_printer(const std::string &name, const std::vector<T> &values);
}
```

---

## Module Relationships

```
               Proof Systems          Signature Schemes
                     |                /        |        \
                     |               /         |         \
              scalar_transcript    scalar_transcript     |
              (Ed25519 proofs)     (CLSAG, Triptych)     |
                     |                |         |        |
                     |          gray_code  dedupe_sort
                     |         (Triptych) (ring sigs)
                     |
              constant_time  <-- checksum verification, MAC comparison
                     |
                  hd_keys  <-- BIP-32/44 key derivation
                     |
            wide_reduction  <-- SHA-512 -> scalar (RFC 8032)
                     |
               string_helper  <-- debug/benchmark output formatting
```

---

## References

| Topic | Link |
|-------|------|
| Fiat-Shamir heuristic | [Fiat & Shamir, 1986][fiat-shamir] |
| BIP-32 HD key derivation | [BIP-0032: Hierarchical Deterministic Wallets][bip32] |
| BIP-44 multi-account structure | [BIP-0044: Multi-Account Hierarchy][bip44] |
| SLIP-10 Ed25519 derivation | [SLIP-0010: Universal private key derivation][slip10] |
| Timing side-channel attacks | [Brumley & Boneh, 2003: Remote timing attacks are practical][timing-attack] |
| Gray codes | [Knuth, TAOCP Vol. 4A, Chapter 7.2.1.1][gray-code] |

[fiat-shamir]: https://link.springer.com/chapter/10.1007/3-540-47721-7_12
[bip32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[bip44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
[slip10]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[timing-attack]: https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf
[gray-code]: https://www-cs-faculty.stanford.edu/~knuth/taocp.html
