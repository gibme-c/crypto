// Copyright (c) 2020-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/**
 * @file crypto.h
 * @brief Standalone C++17 cryptographic primitive library built around Ed25519 elliptic curve operations.
 *
 * Include this single header to access the full API: hashing (SHA3, Argon2), key
 * derivation (BIP-39/BIP-32/SLIP-10), signatures (Ed25519, Borromean, MLSAG, CLSAG, Triptych),
 * range proofs (Bulletproofs/+/++), Pedersen commitments, RingCT, VRF, adapter signatures,
 * Merkle trees, encoding (Base58, addresses, mnemonics), and hierarchical deterministic keys.
 * Link against the `crypto-static` CMake target to pull in all dependencies.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

// Core
#include <core/crypto_common.h>
#include <core/crypto_config.h>
#include <core/crypto_constants.h>
#include <dleq/dleq.h>
#include <dleq/dleq_proof_t.h>

// Types
#include <types/entropy_t.h>
#include <types/hash_t.h>
#include <types/hash_vector_t.h>
#include <types/hd_key_t.h>
#include <types/point_t.h>
#include <types/point_vector_t.h>
#include <types/scalar_t.h>
#include <types/scalar_vector_t.h>
#include <types/secret_key_t.h>
#include <types/seed_t.h>

// Helpers
#include <helpers/dedupe_and_sort_keys.h>
#include <helpers/gray_code_generator_t.h>
#include <helpers/hd_keys.h>
#include <helpers/math_helpers.h>
#include <helpers/scalar_transcript_t.h>
#include <helpers/string_helper.h>
#include <helpers/wide_reduction.h>
#include <randompp.hpp>

// Base58
#include <base58/base58.h>
#include <base58/cn_base58.h>

// Address Encoding
#include <addresses/address_encoding.h>

// Mnemonics
#include <mnemonics/mnemonics.h>

// SLIP-39
#include <slip39/slip39.h>

// Ed25519
#include <ed25519/rfc8032.h>
#include <ed25519/signature.h>
#include <ed25519/signature_t.h>

// Ring Signatures
#include <borromean/borromean.h>
#include <borromean/borromean_signature_t.h>
#include <clsag/clsag.h>
#include <clsag/clsag_signature_t.h>
#include <mlsag/mlsag.h>
#include <mlsag/mlsag_signature_t.h>
#include <triptych/triptych.h>
#include <triptych/triptych_signature_t.h>

// Adapter Signatures
#include <adapter_signature/adapter_signature.h>
#include <adapter_signature/adapter_signature_t.h>

// RingCT
#include <ringct/ringct.h>

// Range Proofs
#include <bulletproofs/bulletproof_t.h>
#include <bulletproofs/bulletproofs.h>
#include <bulletproofsplus/bulletproof_plus_t.h>
#include <bulletproofsplus/bulletproofsplus.h>
#include <bulletproofspp/bulletproof_pp_t.h>
#include <bulletproofspp/bulletproofspp.h>

// VRF
#include <vrf/vrf.h>
#include <vrf/vrf_proof_t.h>

// Merkle
#include <merkle/merkle.h>

// Integration
#include <integration/audit.h>

#endif // CRYPTO_H
