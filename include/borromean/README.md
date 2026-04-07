# Borromean Ring Signature

A Borromean ring signature proves knowledge of one secret key in a set of public
keys without revealing which one. The name comes from Borromean rings -- three
interlocking rings where removing any one frees the other two.

**Namespace**: `Crypto::RingSignature::Borromean`
**Header**: [`borromean.h`](borromean.h)
**Reference**: [Maxwell & Poelstra, 2015][borromean-paper]

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [How It Works (ELI5)](#how-it-works-eli5) | Ring signatures explained with a drawer of signet rings |
| [API](#api) | Ring signature generation and verification |
| [Signature Structure](#signature-structure) | Layout of the borromean_signature_t |
| [Use Cases](#use-cases) | Privacy-preserving protocols |
| [Domain Constants](#domain-constants) | Domain separator indices |
| [References](#references) | Papers and specifications |

---

## How It Works (ELI5)

Imagine you have a **drawer full of signet rings**. Each ring belongs to a
different person, and one of them is yours. You want to seal a letter in
a way that proves *one of the owners of these rings* sealed it, without
anyone being able to tell which ring was actually used.

A **ring signature** does exactly that with cryptography. You gather up
a bunch of public keys (yours plus some decoys), and you produce a signature
that only works if you know the secret key for **at least one** of them.
The verifier can tell the signature is valid, but not which key in the
ring was the real signer. From the outside, everyone in the ring looks
equally suspicious.

There's one clever extra piece: the **key image**. Every time you sign,
a unique "tag" is published alongside the signature. The tag is derived
from your secret key in a one-way fashion -- it doesn't reveal which key
you are, but it's always the same for the same secret. So if someone tries
to spend the same coin twice, the network sees the same tag show up twice
and rejects the second one. This catches double-spends without breaking
anonymity.

Borromean is the **original, simple variant** of this idea. It works, it's
easy to understand, and it's well-studied. Its main drawback is size: the
signature grows *linearly* with the ring -- every extra decoy adds another
64 bytes. Newer schemes like CLSAG (half the size) and Triptych (logarithmic
size) have mostly replaced it for transaction use, but Borromean is still
useful where simplicity matters more than bytes.

---

```
+----------------------------------------------------------+
|                 Borromean Ring Signature                  |
|                                                          |
|   Ring: {K0, K1, K2, ..., K_{n-1}}                      |
|   Signer knows: x such that K_real = x*G                |
|                                                          |
|   Signature proves:                                      |
|     "I know the secret key for ONE of these public keys" |
|     without revealing which one.                         |
|                                                          |
|   Key image: I = x*Hp(K_real)                            |
|     Deterministic -- same key always produces same I.    |
|     Used for double-spend detection.                     |
|                                                          |
|   Signature size: 64 bytes x ring_size                   |
+----------------------------------------------------------+
```

---

## API

```cpp
// Sign (signer index auto-detected from secret key).
// secret_key: the one-time secret key for the output being spent.
// ring_public_keys: all public keys in the ring (real + decoys).
auto [ok, sig] = Crypto::RingSignature::Borromean::generate_ring_signature(
    digest, secret_key, ring_public_keys);

// Sign with explicit signer index (if you already know your position in the ring)
auto [ok, sig] = Crypto::RingSignature::Borromean::generate_ring_signature(
    digest, secret_key, ring_public_keys, real_index);

// The key image must be computed separately -- it is NOT part of the signature.
// It is published alongside the signature for double-spend detection.
auto real_public_key = secret_key * Crypto::G;
auto key_image = Crypto::generate_key_image(real_public_key, secret_key);

// Verify: the verifier needs the key image, the ring, and the signature.
bool valid = Crypto::RingSignature::Borromean::check_ring_signature(
    digest, key_image, ring_public_keys, sig);
```

---

## Signature Structure

```cpp
struct borromean_signature_t {
    std::vector<signature_t> signatures;  // one (L, R) pair per ring member
};
```

---

## Use Cases

- Simple linkable ring signatures for privacy-preserving protocols
- Transaction input authorization where the signer's identity must be hidden
  among a set of decoys
- Anonymous authentication (prove you are a member of a group without
  revealing which member)

**Note:** Borromean does **not** support Pedersen commitment binding. This
means it proves "I know one of these keys" but cannot simultaneously prove
"and the committed amount in my input matches my pseudo-commitment." For
confidential transactions that need both signer anonymity and amount hiding,
use [CLSAG](../clsag/README.md) or [MLSAG](../mlsag/README.md) instead
(which support optional commitment binding) or
[Triptych](../triptych/README.md) (which requires it).

---

## Domain Constants

| Indices | Subsystem |
|---------|-----------|
| 4 | Borromean |

---

## References

| Topic | Link |
|-------|------|
| Borromean ring signatures | [Maxwell & Poelstra, 2015][borromean-paper] |

[borromean-paper]: https://raw.githubusercontent.com/Blockstream/borromean_paper/master/borromean_draft_0.01_34241bb.pdf
