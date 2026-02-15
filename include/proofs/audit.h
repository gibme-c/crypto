// Copyright (c) 2020, Brandon Lehmann
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
 * @file audit.h
 * @brief Ownership and output proofs for selective disclosure.
 *
 * Sometimes you need to prove to a third party that you own certain outputs or keys
 * without revealing your secret keys. This module generates and verifies compact
 * proofs (encoded as Base58 strings) that demonstrate ownership by signing with the
 * secret ephemeral keys and providing the resulting key images.
 */

#ifndef CRYPTO_AUDIT_H
#define CRYPTO_AUDIT_H

#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

namespace Crypto::Audit
{
    /**
     * Verifies an outputs ownership proof against known public ephemeral keys.
     *
     * Decodes the Base58-encoded proof string, extracts the key images and signatures,
     * and verifies each signature. If all signatures check out, the key images are
     * returned so you can use them for further checks (e.g., detecting double-spends).
     *
     * @param public_ephemerals the public ephemeral keys the proof claims to own
     * @param proof the Base58-encoded proof string
     * @return a tuple of {valid, key_images} -- key_images is populated only when valid is true
     */
    std::tuple<bool, std::vector<crypto_key_image_t>>
        check_outputs_proof(const std::vector<crypto_public_key_t> &public_ephemerals, const std::string &proof);

    /**
     * Generates a proof that you own the given secret ephemeral keys.
     *
     * For each secret key, this derives the public key and key image, signs a proof
     * of knowledge, and packs everything into a Base58 string. The verifier only needs
     * the public ephemerals (which they already have) and this proof string.
     *
     * @param secret_ephemerals the secret ephemeral scalars you want to prove ownership of
     * @return a tuple of {success, proof_string} -- the Base58-encoded proof
     */
    std::tuple<bool, std::string> generate_outputs_proof(const std::vector<crypto_scalar_t> &secret_ephemerals);
} // namespace Crypto::Audit

#endif
