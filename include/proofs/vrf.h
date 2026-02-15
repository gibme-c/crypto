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
 * @file vrf.h
 * @brief ED25519-VRF (Verifiable Random Function) proof generation and verification.
 *
 * A VRF produces a pseudorandom output along with a proof that the output was computed
 * correctly from a given secret key and input. The verifier can check the proof using
 * only the public key, input, and proof -- without learning the secret key.
 *
 * Two variants are provided:
 * - **Native**: uses SHA-3 and Elligator hash-to-curve (library conventions)
 * - **RFC 9381**: ECVRF-EDWARDS25519-SHA512-ELL2 using SHA-512 throughout
 */

#ifndef CRYPTO_VRF_H
#define CRYPTO_VRF_H

#include <types/crypto_vrf_proof_t.h>

namespace Crypto::VRF
{
    /**
     * Generates a VRF proof and output for the given secret key and input.
     *
     * @param secret_key the prover's secret scalar
     * @param alpha the VRF input (arbitrary byte string)
     * @return (proof, beta) where beta is the VRF output hash
     */
    std::tuple<crypto_vrf_proof_t, crypto_hash_t> prove(
        const crypto_scalar_t &secret_key,
        const std::vector<unsigned char> &alpha);

    /**
     * Verifies a VRF proof and returns the output if valid.
     *
     * @param public_key the prover's public key
     * @param alpha the VRF input
     * @param proof the VRF proof to verify
     * @return (valid, beta) where valid indicates success and beta is the VRF output
     */
    std::tuple<bool, crypto_hash_t> verify(
        const crypto_public_key_t &public_key,
        const std::vector<unsigned char> &alpha,
        const crypto_vrf_proof_t &proof);
} // namespace Crypto::VRF

namespace Crypto::VRF::RFC9381
{
    /**
     * Generates an RFC 9381 VRF proof (ECVRF-EDWARDS25519-SHA512-ELL2).
     *
     * Uses SHA-512 for hash-to-curve, deterministic nonce (HMAC-SHA512),
     * and 16-byte truncated challenge per the RFC specification.
     *
     * @param secret_key the prover's secret scalar
     * @param alpha the VRF input (arbitrary byte string)
     * @return (proof, beta) where beta is the VRF output hash
     */
    std::tuple<crypto_vrf_rfc9381_proof_t, crypto_hash_t> prove(
        const crypto_scalar_t &secret_key,
        const std::vector<unsigned char> &alpha);

    /**
     * Verifies an RFC 9381 VRF proof and returns the output if valid.
     *
     * @param public_key the prover's public key
     * @param alpha the VRF input
     * @param proof the VRF proof to verify
     * @return (valid, beta) where valid indicates success and beta is the VRF output
     */
    std::tuple<bool, crypto_hash_t> verify(
        const crypto_public_key_t &public_key,
        const std::vector<unsigned char> &alpha,
        const crypto_vrf_rfc9381_proof_t &proof);
} // namespace Crypto::VRF::RFC9381

#endif // CRYPTO_VRF_H
