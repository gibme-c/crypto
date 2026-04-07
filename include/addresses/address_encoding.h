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
 * @file address_encoding.h
 * @brief Checksummed address encoding for single-key and dual-key (spend+view) formats.
 *
 * Addresses combine a network prefix, one or two public keys, and a checksum into a
 * single human-readable string. The dual-key format encodes both a spend key and a
 * view key, which is common in privacy-preserving systems where the view key allows
 * read-only access to incoming transactions. Both standard Base58 and block-based
 * Base58 encodings are supported.
 */

#ifndef CRYPTO_ADDRESS_ENCODING_H
#define CRYPTO_ADDRESS_ENCODING_H

#include <types/point_t.h>

namespace Crypto::Address
{
    /** @brief Standard Base58 address encoding with checksum. */
    namespace Base58
    {
        /**
         * Decodes a Base58 address into its prefix and public key components.
         *
         * For single-key addresses, only the first key is meaningful; the second
         * will be empty. For dual-key addresses, both keys are populated.
         *
         * @param address the Base58-encoded address string
         * @return a tuple of {success, prefix, public_key_1, public_key_2}
         */
        std::tuple<bool, uint64_t, public_key_t, public_key_t> decode(const std::string &address);

        /**
         * Encodes a single public key with a network prefix into a Base58 address.
         *
         * @param prefix the network prefix (identifies the address type/network)
         * @param public_key the public key to encode
         * @return the checksummed Base58 address string
         */
        std::string encode(const uint64_t &prefix, const public_key_t &public_key);

        /**
         * Encodes a spend key and view key with a network prefix into a dual-key Base58 address.
         *
         * @param prefix the network prefix (identifies the address type/network)
         * @param public_spend the public spend key
         * @param public_view the public view key (allows read-only transaction scanning)
         * @return the checksummed Base58 address string
         */
        std::string encode(const uint64_t &prefix, const public_key_t &public_spend, const public_key_t &public_view);
    } // namespace Base58

    /** @brief Block-based Base58 address encoding with checksum. */
    namespace CNBase58
    {
        /**
         * Decodes a block-based Base58 address into its prefix and public key components.
         *
         * @param address the block-based Base58-encoded address string
         * @return a tuple of {success, prefix, public_key_1, public_key_2}
         */
        std::tuple<bool, uint64_t, public_key_t, public_key_t> decode(const std::string &address);

        /**
         * Encodes a single public key with a network prefix into a block-based Base58 address.
         *
         * @param prefix the network prefix
         * @param public_key the public key to encode
         * @return the checksummed block-based Base58 address string
         */
        std::string encode(const uint64_t &prefix, const public_key_t &public_key);

        /**
         * Encodes a spend key and view key with a network prefix into a dual-key block-based Base58 address.
         *
         * @param prefix the network prefix
         * @param public_spend the public spend key
         * @param public_view the public view key
         * @return the checksummed block-based Base58 address string
         */
        std::string encode(const uint64_t &prefix, const public_key_t &public_spend, const public_key_t &public_view);
    } // namespace CNBase58
} // namespace Crypto::Address

#endif
