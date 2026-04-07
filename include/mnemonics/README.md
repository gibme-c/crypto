# BIP-39 Mnemonics

This module converts raw entropy (128 or 256 bits) into a sequence of
12 or 24 common words that humans can write down and store safely. A
built-in SHA-256 checksum catches transcription errors.

**Namespace**: `Crypto::Mnemonics`
**Header**: [mnemonics.h](mnemonics.h)
**Reference**: [BIP-0039: Mnemonic code for generating deterministic keys][bip39]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Word phrases as wallet backups |
| [Overview](#overview) | How BIP-39 encoding works |
| [API](#api) | Encode, decode, and utility functions |
| [Scenario](#scenario-backing-up-and-restoring-a-wallet) | Backing up and restoring a wallet |
| [Language Support](#language-support) | Multi-language word lists (10 languages) |
| [Cross-Compilation Note](#cross-compilation-note) | Where types are declared vs compiled |

---

## How It Works (ELI5)

Imagine someone hands you the master key to a vault that holds everything you
own -- your savings, your house deeds, your photos, all of it. The key is a
string of 64 random hex characters. Now try to memorize it. Or write it down
without making a single typo. Or read it aloud over the phone. Impossible.

BIP-39 solves this by turning that hex string into a list of **12 or 24
ordinary English words** drawn from a standard 2,048-word dictionary. Words
like `abandon`, `apple`, `mountain`, `zebra`. They're easy to read, easy to
write, easy to remember, and easy to dictate. The choice of 12 vs 24 is a
trade-off between length and entropy: 12 words encode 128 bits of secret,
24 words encode 256 bits. Either way, the last word is a **checksum** -- if
you mistype any word, the math doesn't work out and your wallet refuses to
load. The error gets caught before any coins move.

The same words work in any BIP-39-compatible wallet, in any country, on any
device, forever. That's the whole point: a backup format you can write on paper,
store in a safe, and recover from years later.

---

## Overview

BIP-39 mnemonic encoding converts raw entropy into a sequence of common words
that humans can write down and store safely. A built-in SHA-256 checksum catches
transcription errors.

Your entire wallet -- every key, every address, every coin -- comes from a
single 16- or 32-byte secret (the entropy). But raw hex is impossible to
memorize and easy to mistype. BIP-39 converts those bytes into 12 or 24 common
English words (12 words for 128 bits of entropy, 24 words for 256 bits). You
write the words on paper, store them safely, and you can rebuild your entire
wallet from those words years later -- even on different software, different
hardware, different countries.

```
Entropy (128 or 256 bits)
+--+--+--+--+--+--+--+--+ ... +--+--+--+--+
|  |  |  |  |  |  |  |  |     |  |  |  |  |
+--+--+--+--+--+--+--+--+ ... +--+--+--+--+
                    |
                    v  SHA-256, take first (entropy_bits / 32) bits as checksum
+--+--+--+--+--+--+--+--+ ... +--+--+--+--+------+
| entropy                                  | csum |
+--+--+--+--+--+--+--+--+ ... +--+--+--+--+------+
   128 bits -> + 4-bit checksum  = 132 bits = 12 words
   256 bits -> + 8-bit checksum  = 264 bits = 24 words
                    |
                    v  split into groups of 11 bits each
+------+------+------+------+------+------+ ... +------+
| 0742 | 1891 | 0023 | 1456 | 0891 | 0134 |     | 1923 |
+------+------+------+------+------+------+ ... +------+
  12 or 24 indices into a 2048-word list
                    |
                    v  look up each index in the word list
["hockey", "tunnel", "acid", "require", "ivory", "arrest",
 "sweet", "east", "ocean", "absurd", "glue", "visit", ... ]
```

---

## API

```cpp
// Encode entropy to word sequence
std::vector<std::string> encode(
    const entropy_t &entropy,
    const Language::Language &language = Language::Language::ENGLISH);

// Decode word sequence back to entropy
entropy_t decode(
    const std::vector<std::string> &words,
    const Language::Language &language = Language::Language::ENGLISH);

// Utility
std::vector<Language::Language> languages();      // all supported languages
std::vector<std::string> word_list(              // full 2048-word list
    const Language::Language &language = Language::Language::ENGLISH);
std::vector<std::string> word_list_trimmed(      // unique-prefix shortened
    const Language::Language &language = Language::Language::ENGLISH);
std::optional<size_t> word_index(                // look up a single word
    const std::string &word,
    const Language::Language &language = Language::Language::ENGLISH);
```

---

## Scenario: Backing Up and Restoring a Wallet

```
FUNCTION wallet_backup_and_restore():
    // Alice creates a new wallet. She needs to back up the master
    // secret so she can restore it if her phone breaks.

    // --- Generate entropy -------------------------------------------
    entropy = entropy_t::random()
    // entropy = 32 random bytes (256 bits of secret)
    // (use entropy_t::random(16) for 12-word mnemonics instead)

    // --- Encode as 12 or 24 words -----------------------------------
    words = Mnemonics::encode(entropy)
    // For 256-bit entropy:
    //   words = ["abandon", "ability", "able", "about", "above", "absent",
    //            "absorb", "abstract", "absurd", "abuse", "access", "accident",
    //            "account", "accuse", "achieve", "acid", "across", "act",
    //            "action", "adapt", "add", "addict", "address", "adjust"]
    //   (24 words; actual words depend on the random entropy)
    //
    // For 128-bit entropy:
    //   words = ["abandon", "ability", "able", "about", "above", "absent",
    //            "absorb", "abstract", "absurd", "abuse", "access", "accident"]
    //   (12 words instead of 24)

    // Alice writes these words on paper and stores it in a safe.
    // She does NOT store them on her computer or in the cloud.

    // --- Derive the wallet ------------------------------------------
    seed = seed_t(entropy, "optional passphrase")
    spend_key = seed.generate_child_key("m/44'/0'/0'/0'/0'")
    view_key  = seed.generate_child_key("m/44'/0'/0'/1'/0'")
    // The wallet is now fully operational.

    // --- Three years later: Alice's phone breaks --------------------
    // She buys a new phone, installs the wallet app, and enters
    // her recovery words:

    recovered_entropy = Mnemonics::decode(words)
    // recovered_entropy == entropy (identical!)

    // The wallet derives all keys from the entropy:
    recovered_seed = seed_t(recovered_entropy, "optional passphrase")
    recovered_spend = recovered_seed.generate_child_key("m/44'/0'/0'/0'/0'")
    recovered_view  = recovered_seed.generate_child_key("m/44'/0'/0'/1'/0'")
    // All keys match -- Alice has her wallet back!

    // --- What if she mistyped a word? -------------------------------
    bad_words = words
    bad_words[5] = "absent"   // she wrote "absorb" but typed "absent"
    // The BIP-39 checksum catches this:
    //   The last word encodes a checksum of the entropy.
    //   If any word is wrong, the decode detects the mismatch.
```

**Beyond wallet backup:** BIP-39 encoding is useful anywhere a human needs to
reliably transcribe a cryptographic secret -- backup encryption keys, root
secrets for certificate hierarchies, or master keys for hardware security
modules. The word-based format is resilient to handwriting errors and can be
read aloud over the phone without ambiguity.

---

## Language Support

**Directory**: [languages/](languages/)

BIP-39 mnemonic word lists in 10 languages. Each list contains exactly 2048
words selected so that the first few characters uniquely identify each word
(enabling prefix-based input).

| Language | Enum | Unique Prefix | Words |
|----------|------|---------------|-------|
| English | `ENGLISH` (3) | 4 chars | 2048 |
| Chinese Simplified | `CHINESE_SIMPLIFIED` (0) | 1 char | 2048 |
| Chinese Traditional | `CHINESE_TRADITIONAL` (1) | 1 char | 2048 |
| Czech | `CZECH` (2) | 4 chars | 2048 |
| French | `FRENCH` (4) | 4 chars | 2048 |
| Italian | `ITALIAN` (5) | 4 chars | 2048 |
| Japanese | `JAPANESE` (6) | varies | 2048 |
| Korean | `KOREAN` (7) | 2 chars | 2048 |
| Portuguese | `PORTUGUESE` (8) | 4 chars | 2048 |
| Spanish | `SPANISH` (9) | 4 chars | 2048 |

**Build option**: Define `-DENGLISH_ONLY` to compile only the English word
list, reducing binary size when multi-language support is not needed.

### Language API

```cpp
// Get the word list for a language
std::vector<std::string> select_word_list(const Language &language);

// Get the minimum unique prefix length
size_t select_word_list_prefix(const Language &language);
```

---

## Cross-Compilation Note

The types `entropy_t` and `seed_t` are **declared** in the `types/` module
but are **compiled** as part of the `crypto-mnemonics` library target. This
means that code using these types must link against `crypto-mnemonics` even
though the headers live in `types/`.

---

## Checksum

| Module | Checksum Algorithm | Size | Error Detection |
|--------|--------------------|------|-----------------|
| BIP-39 | SHA-256 | 4-8 bits | Transcription errors |

---

## References

| Topic | Link |
|-------|------|
| BIP-39 mnemonic encoding | [BIP-0039: Mnemonic code for generating deterministic keys][bip39] |

[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
