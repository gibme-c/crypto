# Standalone Cryptography Library

This repository a standalone cryptographic primitive wrapper library that can be included in various other projects in a variety of development environments.

The source code is designed in such a way (using overloads for the majority of cryptographic functions) to make the code base easy for humans to read.

### Features

* Core Structure Types
  * All structures have overloads for [pretty printing](https://wikipedia.org/wiki/Prettyprint) to screen
  * Primitive Structures
    * `crypto_hash_t`: 256-bit [Hash](https://wikipedia.org/wiki/Hash_function)
    * `crypto_point_t`: [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) Elliptic Curve Point
      * Caching of commonly used `ge` types
      * Simple overloads for point:
        * Addition
        * Subtraction
      * Aliases:
        * `crypto_public_key_t`
        * `crypto_derivation_t`
        * `crypto_key_image_t`
        * `crypto_pedersen_commitment_t`
    * `crypto_scalar_t`: [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) Elliptic Curve Scalar
      * Conform to [RFC-8032](https://datatracker.ietf.org/doc/html/rfc8032) clamping
      * Simple overloads for scalar:
        * Addition
        * Subtraction
        * Multiplication (with scalars **or** points)
        * Division
      * Aliases:
        * `crypto_blinding_factor_t`
  * Hierarchical Deterministic Keys
    * `crypto_entropy_t`: [BIP-0039](https://en.bitcoin.it/wiki/BIP_0039) [Entropy](https://en.wikipedia.org/wiki/Entropy_(computing))
      * Supports 12-word (128-bit) or 24-word (256-bit) entropy values
      * Allows for the encoding and decoding of the entropy to/from [Mnemonic](https://en.wikipedia.org/wiki/Mnemonic) words or phrases
      * Optionally Encodes the [unix time](https://wikipedia.org/wiki/Unix_time) the entropy was created into the entropy
    * `crypto_seed_t`: [BIP-0039](https://en.bitcoin.it/wiki/BIP_0039) Seed
      * Allows for generation of the seed using `crypto_entropy_t` or by loading raw bytes
        * Allows for specifying a [passphrase](https://en.wikipedia.org/wiki/Passphrase) during initialization
        * Allows for specifying the [HMAC](https://en.wikipedia.org/wiki/HMAC) salt
      * Generates the [BIP-0032](https://en.bitcoin.it/wiki/BIP_0032) root (or "master") key & chain code
      * Allows for generating child keys
        * **Note** All paths are fully hardened per [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
    * `crypto_hd_key_t`: [BIP-0044](https://en.bitcoin.it/wiki/BIP_0044) Hierarchical Deterministic Key
      * Equivalent to a private/public [keypair](https://en.wikipedia.org/wiki/Public-key_cryptography)
      * Allows for generating child keys
        * **Note** All paths are fully hardened per [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
    * * `crypto_secret_key_t`: [ED25519](https://datatracker.ietf.org/doc/html/rfc8032) Secret Keys
      * Allows for loading a RFC-8032 *private* key and then the scalar value and point are derived using SHA512
      * Overloads to RFC-8032 compliant `crypto_scalar_t` when required
  * Vector Types
    * `crypto_hash_vector_t`
    * `crypto_point_vector_t`
      * Simple overloads for:
        * Addition
        * Subtraction
        * Multiplication with scalars
    * `crypto_scalar_vector_t`
      * Simple overloads for:
        * Addition
        * Subtraction
        * Multiplication
  * Cryptographic Signature Types
    * `crypto_signature_t`: 512-bit [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) signature
    * `crypto_borromean_signature_t`: [Borromean](https://github.com/Blockstream/borromean_paper/raw/master/borromean_draft_0.01_34241bb.pdf) Ring Signature
    * `crypto_clsag_signature_t`: [CLSAG](https://eprint.iacr.org/2019/654.pdf) Ring Signature
    * `crypto_triptych_signature_t`: [Triptych](https://eprint.iacr.org/2020/018.pdf) Signature
  * Proof Types
    * `crypto_bulletproof_t`: [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf)
    * `crypto_bulletproof_plus_t`: [Bulletproofs+](https://eprint.iacr.org/2020/735.pdf)
* Core Functionality
  * [Stealth Addresses](https://bytecoin.org/old/whitepaper.pdf)
  * Auditing Methods
    * Prove & Verify output ownership with linking tags (key images)
  * [SHA3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) (256-bit)
    * Simple hashing via `crypto_hash_t::sha3()`
    * Simple [key stretching](https://wikipedia.org/wiki/Key_stretching) via `crypto_hash_t::sha3_slow()`
  * [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
    * Simple AES wrapper encrypting/decrypting data to/from hexadecimal encoded strings
  * [Argon2](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf) Hashing
    * Argon2d via `crypto_hash_t::argon2d()`
    * Argon2i via `crypto_hash_t::argon2i()`
    * Argon2id via `crypto_hash_t::argon2id()`
  * Address Encoding with [Checksums](https://wikipedia.org/wiki/Checksum)
    * Dual-key (spend & view)
    * Single-key
    * Base58 or CryptoNote Base58 encoding
  * [Base58 Encoding](https://tools.ietf.org/html/draft-msporny-base58-02)
    * With or Without Checksum Calculations/Checks
    * **Note:** This implementation is **not** block-based and will not work with block-based Base58 encoding (ie. CryptoNote)
  * [CryptoNote Base58 Encoding](https://tools.ietf.org/html/draft-msporny-base58-02)
    * With or Without Checksum Calculations/Checks
    * **Note:** This implementation is block-based and will not work with non-block-based Base58 encoding
  * [Mnemonic](https://en.wikipedia.org/wiki/Mnemonic) Encoding
    * Utilizes SHA3 instead of CRC32 for checksum generation
    * Languages
      * [Chinese Simplified](https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_simplified.txt) 
      * [Chinese Traditional](https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_traditional.txt)
      * [Czech](https://github.com/bitcoin/bips/blob/master/bip-0039/czech.txt)
      * [English language](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)
      * [French](https://github.com/bitcoin/bips/blob/master/bip-0039/french.txt)
      * [Italian](https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt)
      * [Japanese](https://github.com/bitcoin/bips/blob/master/bip-0039/japanese.txt)
      * [Korean](https://github.com/bitcoin/bips/blob/master/bip-0039/korean.txt)
      * [Portuguese](https://github.com/bitcoin/bips/blob/master/bip-0039/portuguese.txt)
      * [Spanish](https://github.com/bitcoin/bips/blob/master/bip-0039/spanish.txt)
  * [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) Primitives
  * Scalar Transcripts
    * Easily generates deterministic scalar values based upon repetitive `update()` calls
* Signature Generation / Verification
  * Message Signing & Validation
    * [RFC-8032 ED25519](https://tools.ietf.org/html/rfc8032)
    * Non-RFC 8032 (e.g. CryptoNote)
  * [Borromean](https://github.com/Blockstream/borromean_paper/raw/master/borromean_draft_0.01_34241bb.pdf) Ring Signatures
  * [CLSAG](https://eprint.iacr.org/2019/654.pdf) Ring Signatures
    * **Optional** use of pedersen commitment to zero proving
  * [Triptych](https://eprint.iacr.org/2020/018.pdf) Signatures
    * **Requires** use of pedersen commitment to zero proving
* [Zero-knowledge proofs](https://wikipedia.org/Zero-knowledge-proof)
  * [RingCT](https://eprint.iacr.org/2015/1098.pdf)
    * [Pedersen Commitments](https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF)
    * Pseudo Commitments
    * Blinding Factors
    * Amount Masking
  * [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) Range Proofs
    * Variable bit length proofs (1 to 64 bits)
    * No limits to number of values proved or verified in a single call
    * Batch Verification
    * Implements caching of common points for faster repeat calls to `prove()` and `verify()`
  * [Bulletproofs+](https://eprint.iacr.org/2020/735.pdf) Range Proofs
    * Variable bit length proofs (1 to 64 bits)
    * No limits to number of values proved or verified in a single call
    * Batch Verification
    * Implements caching of common points for faster repeat calls to `prove()` and `verify()`
* [Serialization](https://github.com/gibme-c/serialization-cpp)
  * Byte/Binary Serialization & De-Serialization
  * Structure to/from [JSON](https://wikipedia.org/wiki/JSON) provided via [RapidJSON](https://rapidjson.org)
  * Structure to/from [Hexadecimal](https://wikipedia.org/wiki/Hexadecimal) encoded string representations

## C++ Library

A CMakeLists.txt file enables easy builds on most systems. 

The CMake build system builds an optimized static library for you. 

However, it is best to simply include this project in your project as a dependency with your CMake project.

Please reference your system documentation on how to compile with CMake.

To use this library in your project(s) simply link against the build target (`crypto-static`) and include the following in your relevant source or header file(s).

```c++
#include <crypto.h>
```

### Documentation

C++ API documentation can be found in the headers (.h)

## Cloning this Repository

This repository uses submodules, make sure you pull those before doing anything if you are cloning this project.

```bash
git clone --recursive https://github.com/gibme-c/crypto
cd crypto
```

### As a dependency
```bash
git submodule add https://github.com/gibme-c/crypto external/crypto
git submodule update --init --recursive
```

## License

External references are provided via libraries in the Public Domain (Unlicense), MIT, and/or BSD from their respective parties. Please see CREDITS or the packages in `external/` for more information.

This wrapper library is provided under the BSD-3-Clause license found in the LICENSE file.

Please make sure when using this library that you follow the licensing requirements set forth in all licenses.
