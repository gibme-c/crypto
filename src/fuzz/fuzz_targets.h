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

#ifndef CRYPTO_FUZZ_TARGETS_H
#define CRYPTO_FUZZ_TARGETS_H

// ---------------------------------------------------------------------------
// Single declaration site for every per-module fuzz entry point.
//
// Every fuzz_target_<mod>.cpp translation unit defines exactly one of these
// functions. The smoke driver iterates them via the FUZZ_TARGET_LIST macro;
// the libFuzzer stub generator instantiates one LLVMFuzzerTestOneInput shim
// per entry, each dispatching to the matching fuzz_one_<mod>.
//
// Order matches the CMake module layering order for visual consistency with
// the root CMakeLists.txt add_subdirectory block.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>

extern "C"
{
    // Types layer
    void fuzz_one_scalar(const uint8_t *data, size_t size);
    void fuzz_one_point(const uint8_t *data, size_t size);
    void fuzz_one_hash(const uint8_t *data, size_t size);
    void fuzz_one_entropy(const uint8_t *data, size_t size);
    void fuzz_one_hd_keys(const uint8_t *data, size_t size);

    // Core layer
    void fuzz_one_aes(const uint8_t *data, size_t size);
    void fuzz_one_transcript(const uint8_t *data, size_t size);

    // Encoding layer
    void fuzz_one_base58(const uint8_t *data, size_t size);
    void fuzz_one_addresses(const uint8_t *data, size_t size);
    void fuzz_one_mnemonics(const uint8_t *data, size_t size);
    void fuzz_one_slip39(const uint8_t *data, size_t size);

    // Signature layer
    void fuzz_one_signature(const uint8_t *data, size_t size);
    void fuzz_one_rfc8032(const uint8_t *data, size_t size);
    void fuzz_one_dleq(const uint8_t *data, size_t size);
    void fuzz_one_adapter(const uint8_t *data, size_t size);

    // Ring signature layer
    void fuzz_one_borromean(const uint8_t *data, size_t size);
    void fuzz_one_clsag(const uint8_t *data, size_t size);
    void fuzz_one_mlsag(const uint8_t *data, size_t size);
    void fuzz_one_triptych(const uint8_t *data, size_t size);

    // RingCT
    void fuzz_one_ringct(const uint8_t *data, size_t size);

    // Range proofs
    void fuzz_one_bp(const uint8_t *data, size_t size);
    void fuzz_one_bpplus(const uint8_t *data, size_t size);
    void fuzz_one_bppp(const uint8_t *data, size_t size);

    // VRF
    void fuzz_one_vrf(const uint8_t *data, size_t size);

    // Merkle
    void fuzz_one_merkle(const uint8_t *data, size_t size);

    // Integration
    void fuzz_one_audit(const uint8_t *data, size_t size);
} // extern "C"

// ---------------------------------------------------------------------------
// FUZZ_TARGET_LIST(X) — X-macro over every registered target.
// Each entry: X(name_string, function_symbol). The smoke driver and the
// libFuzzer stub generator both consume this list; adding a new target
// requires ONLY:
//   (1) declare fuzz_one_<mod> above
//   (2) add the X(...) entry below
//   (3) create src/fuzz/fuzz_target_<mod>.cpp
//   (4) add the .cpp to src/fuzz/CMakeLists.txt CRYPTO_FUZZ_TARGET_SOURCES
// ---------------------------------------------------------------------------
#define CRYPTO_FUZZ_TARGET_LIST(X)       \
    X("scalar", fuzz_one_scalar)         \
    X("point", fuzz_one_point)           \
    X("hash", fuzz_one_hash)             \
    X("entropy", fuzz_one_entropy)       \
    X("hd_keys", fuzz_one_hd_keys)       \
    X("aes", fuzz_one_aes)               \
    X("transcript", fuzz_one_transcript) \
    X("base58", fuzz_one_base58)         \
    X("addresses", fuzz_one_addresses)   \
    X("mnemonics", fuzz_one_mnemonics)   \
    X("slip39", fuzz_one_slip39)         \
    X("signature", fuzz_one_signature)   \
    X("rfc8032", fuzz_one_rfc8032)       \
    X("dleq", fuzz_one_dleq)             \
    X("adapter", fuzz_one_adapter)       \
    X("borromean", fuzz_one_borromean)   \
    X("clsag", fuzz_one_clsag)           \
    X("mlsag", fuzz_one_mlsag)           \
    X("triptych", fuzz_one_triptych)     \
    X("ringct", fuzz_one_ringct)         \
    X("bp", fuzz_one_bp)                 \
    X("bpplus", fuzz_one_bpplus)         \
    X("bppp", fuzz_one_bppp)             \
    X("vrf", fuzz_one_vrf)               \
    X("merkle", fuzz_one_merkle)         \
    X("audit", fuzz_one_audit)

#endif // CRYPTO_FUZZ_TARGETS_H
