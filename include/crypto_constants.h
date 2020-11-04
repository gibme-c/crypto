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

#ifndef CRYPTO_CONSTANTS_H
#define CRYPTO_CONSTANTS_H

#include <types/crypto_hash_t.h>
#include <types/crypto_scalar_t.h>

const auto SALT_DOMAIN = crypto_scalar_t("202053504f4e534f52454420425920444f4e5554532041524520474f4f442020");

/**
 * Helper method to generate a deterministic scalar for salting purposes
 *
 * @param index
 * @return
 */
static inline crypto_scalar_t generate_salt_scalar(size_t index)
{
    return crypto_hash_t::sha3_slow(SALT_DOMAIN, index).scalar();
}

/**
 * Helper method to generate a deterministic point for salting purposes
 *
 * @param index
 * @return
 */
static inline crypto_point_t generate_salt_point(size_t index)
{
    return crypto_hash_t::sha3_slow(SALT_DOMAIN, index).point();
}

/**
 * Separate hash domains are used at different methods during the construction and verification
 * processes within this library to avoid scalar collisions in different stages of the
 * construction and verification of those structures
 *
 * TLDR: these are hash salts
 */

const auto DERIVATION_DOMAIN_0 = generate_salt_scalar(0);

const auto SPEND_KEY_DOMAIN_0 = generate_salt_scalar(1);

const auto VIEW_KEY_DOMAIN_0 = generate_salt_scalar(2);

const auto SIGNATURE_DOMAIN_0 = generate_salt_scalar(3);

const auto BORROMEAN_DOMAIN_0 = generate_salt_scalar(4);

const auto CLSAG_DOMAIN_0 = generate_salt_scalar(5);

const auto CLSAG_DOMAIN_1 = generate_salt_scalar(6);

const auto CLSAG_DOMAIN_2 = generate_salt_scalar(7);

const auto DOMAIN_COMMITMENT_MASK_0 = generate_salt_scalar(8);

const auto DOMAIN_AMOUNT_MASK_0 = generate_salt_scalar(9);

const auto TRIPTYCH_DOMAIN_0 = generate_salt_scalar(10);

const auto TRIPTYCH_DOMAIN_1 = generate_salt_point(11);

const auto BULLETPROOFS_DOMAIN_0 = generate_salt_scalar(12);

const auto BULLETPROOFS_DOMAIN_1 = generate_salt_point(13);

const auto BULLETPROOFS_DOMAIN_2 = generate_salt_point(14);

const auto BULLETPROOFS_PLUS_DOMAIN_0 = generate_salt_scalar(15);

const auto BULLETPROOFS_PLUS_DOMAIN_1 = generate_salt_point(16);

const auto BULLETPROOFS_PLUS_DOMAIN_2 = generate_salt_point(17);

const auto OUTPUT_PROOF_DOMAIN = generate_salt_scalar(18);

const auto TRANSCRIPT_BASE = generate_salt_scalar(19);

#endif
