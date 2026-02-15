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
 * @file cn_base58.h
 * @brief Block-based Base58 encoding with deterministic output length.
 *
 * Unlike standard Base58, this variant processes the input in 8-byte blocks, each
 * producing a fixed-width Base58 output. This gives you a deterministic relationship
 * between input length and output length, which is useful for address encoding where
 * you need to know the encoded size ahead of time.
 */

#ifndef CRYPTO_BASE58_CN_H
#define CRYPTO_BASE58_CN_H

#include <serialization.h>
#include <string>
#include <tuple>
#include <vector>

namespace Crypto::CNBase58
{
    /**
     * Decodes a block-based Base58 string into raw bytes.
     *
     * @param input the block-based Base58-encoded string
     * @return a tuple of {success, reader} where reader contains the decoded bytes
     */
    [[nodiscard]] std::tuple<bool, Serialization::deserializer_t> decode(const std::string &input);

    /**
     * Decodes a block-based Base58 string with checksum verification.
     *
     * @param input the block-based Base58-encoded string (with appended checksum)
     * @return a tuple of {success, reader} where reader contains the decoded bytes (without checksum)
     */
    [[nodiscard]] std::tuple<bool, Serialization::deserializer_t> decode_check(const std::string &input);

    /**
     * Encodes raw bytes into a block-based Base58 string.
     *
     * @param input the raw bytes to encode
     * @return the block-based Base58-encoded string
     */
    [[nodiscard]] std::string encode(const std::vector<uint8_t> &input);

    /**
     * Encodes the contents of a deserializer into a block-based Base58 string.
     *
     * @param reader the deserializer containing bytes to encode
     * @return the block-based Base58-encoded string
     */
    [[nodiscard]] std::string encode(const Serialization::deserializer_t &reader);

    /**
     * Encodes the contents of a serializer into a block-based Base58 string.
     *
     * @param writer the serializer containing bytes to encode
     * @return the block-based Base58-encoded string
     */
    [[nodiscard]] std::string encode(const Serialization::serializer_t &writer);

    /**
     * Encodes raw bytes into a block-based Base58 string with an appended checksum.
     *
     * @param input the raw bytes to encode
     * @return the block-based Base58-encoded string with checksum
     */
    [[nodiscard]] std::string encode_check(const std::vector<uint8_t> &input);

    /**
     * Encodes the contents of a deserializer into a block-based Base58 string with checksum.
     *
     * @param reader the deserializer containing bytes to encode
     * @return the block-based Base58-encoded string with checksum
     */
    [[nodiscard]] std::string encode_check(const Serialization::deserializer_t &reader);

    /**
     * Encodes the contents of a serializer into a block-based Base58 string with checksum.
     *
     * @param writer the serializer containing bytes to encode
     * @return the block-based Base58-encoded string with checksum
     */
    [[nodiscard]] std::string encode_check(const Serialization::serializer_t &writer);
} // namespace Crypto::CNBase58

#endif
