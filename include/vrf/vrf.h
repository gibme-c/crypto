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

#include <types/secret_key_t.h>
#include <vrf/vrf_proof_t.h>

namespace Crypto::VRF
{
    /**
     * Generates a VRF proof and output for the given secret key and input.
     *
     * @param secret_key the prover's secret scalar
     * @param alpha the VRF input (arbitrary byte string)
     * @return (proof, beta) where beta is the VRF output hash
     */
    std::tuple<vrf_proof_t, hash_t> prove(const scalar_t &secret_key, const std::vector<unsigned char> &alpha);

    /**
     * Verifies a VRF proof and returns the output if valid.
     *
     * @param public_key the prover's public key
     * @param alpha the VRF input
     * @param proof the VRF proof to verify
     * @return (valid, beta) where valid indicates success and beta is the VRF output
     */
    std::tuple<bool, hash_t>
        verify(const public_key_t &public_key, const std::vector<unsigned char> &alpha, const vrf_proof_t &proof);
} // namespace Crypto::VRF

namespace Crypto::VRF::RFC9381
{
    /**
     * Generates an RFC 9381 VRF proof (ECVRF-EDWARDS25519-SHA512-ELL2, suite 0x04).
     *
     * Implements the spec-compliant construction:
     *  - hash-to-curve: SHA-512 + Elligator2 + cofactor clearing (§5.4.1.2)
     *  - deterministic nonce: `k = SHA-512(SHA-512(seed)[32..64] || h_string) mod q`
     *    per §5.4.2.2 ECVRF_nonce_generation_RFC8032 -- this requires the raw 32-byte
     *    SK seed (the upper half of SHA-512(seed) is the secret PRF key), which is
     *    why this function takes `secret_key_t` rather than `scalar_t`
     *  - 16-byte truncated challenge over (Y, H, Gamma, U, V) per §5.4.3
     *  - response: `s = k + c*x mod q` per §5.1 step 7
     *
     * Validated against RFC 9381 Appendix B.4 KAT vectors (Examples 19-21).
     *
     * @param secret_key the prover's RFC 8032 secret key (32-byte seed)
     * @param alpha the VRF input (arbitrary byte string)
     * @return (proof, beta) where beta is the 32-byte truncation of the 64-byte
     *         VRF output hash defined in §5.2 (`SHA-512(suite || 0x03 || cofactor*Gamma || 0x00)`)
     */
    std::tuple<vrf_rfc9381_proof_t, hash_t>
        prove(const secret_key_t &secret_key, const std::vector<unsigned char> &alpha);

    /**
     * Verifies an RFC 9381 VRF proof and returns the output if valid.
     *
     * @param public_key the prover's public key
     * @param alpha the VRF input
     * @param proof the VRF proof to verify
     * @return (valid, beta) where valid indicates success and beta is the VRF output
     */
    std::tuple<bool, hash_t> verify(
        const public_key_t &public_key,
        const std::vector<unsigned char> &alpha,
        const vrf_rfc9381_proof_t &proof);
} // namespace Crypto::VRF::RFC9381

#endif // CRYPTO_VRF_H
