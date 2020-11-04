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

#ifndef CRYPTO_ADDRESS_ENCODING_H
#define CRYPTO_ADDRESS_ENCODING_H

#include <types/crypto_point_t.h>

namespace Crypto::Address
{
    /**
     * Base58 Address Encoding
     */
    namespace Base58
    {
        /**
         * Decodes the given Base58 string into the prefix and key parts
         *
         * @param address
         * @return
         */
        std::tuple<bool, uint64_t, crypto_public_key_t, crypto_public_key_t> decode(const std::string &address);

        /**
         * Encodes the single public key with the given prefix into Base58
         *
         * @param prefix
         * @param public_key
         * @return
         */
        std::string encode(const uint64_t &prefix, const crypto_public_key_t &public_key);

        /**
         * Encodes the two public keys with the given prefix into Base58
         *
         * @param prefix
         * @param public_spend
         * @param public_view
         * @return
         */
        std::string encode(
            const uint64_t &prefix,
            const crypto_public_key_t &public_spend,
            const crypto_public_key_t &public_view);
    } // namespace Base58

    /**
     * CryptoNote Base58 Address Encoding
     */
    namespace CNBase58
    {
        /**
         * Decodes the given CryptoNote Base58 string into the prefix and key parts
         *
         * @param address
         * @return
         */
        std::tuple<bool, uint64_t, crypto_public_key_t, crypto_public_key_t> decode(const std::string &address);

        /**
         * Encodes the single public key with the given prefix into CryptoNote Base58
         * @param prefix
         * @param public_key
         * @return
         */
        std::string encode(const uint64_t &prefix, const crypto_public_key_t &public_key);

        /**
         * Encodes the two public keys with the given prefix into CryptoNote Base58
         *
         * @param prefix
         * @param public_spend
         * @param public_view
         * @return
         */
        std::string encode(
            const uint64_t &prefix,
            const crypto_public_key_t &public_spend,
            const crypto_public_key_t &public_view);
    } // namespace CNBase58
} // namespace Crypto::Address

#endif
