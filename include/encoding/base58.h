// Copyright (c) 2014-2020, The Bitcoin Core developers
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
 * @file base58.h
 * @brief Standard Base58 encoding and decoding.
 *
 * Base58 is like Base64 but drops visually ambiguous characters (0, O, I, l) and
 * non-alphanumeric characters (+ and /), making it ideal for human-readable strings
 * like addresses. This implementation includes optional checksum variants that append
 * a 4-byte SHA3 hash to detect accidental corruption.
 */

#ifndef CRYPTO_BASE58_H
#define CRYPTO_BASE58_H

#include <serialization.h>

namespace Crypto::Base58
{
    /**
     * Decodes a Base58 string into raw bytes.
     *
     * @param input the Base58-encoded string
     * @return a tuple of {success, reader} where reader contains the decoded bytes
     */
    [[nodiscard]] std::tuple<bool, Serialization::deserializer_t> decode(const std::string &input);

    /**
     * Decodes a Base58 string with checksum verification.
     *
     * First decodes, then verifies that the trailing checksum matches the payload.
     * Returns failure if the checksum does not match (i.e., the data was corrupted).
     *
     * @param input the Base58-encoded string (with appended checksum)
     * @return a tuple of {success, reader} where reader contains the decoded bytes (without checksum)
     */
    [[nodiscard]] std::tuple<bool, Serialization::deserializer_t> decode_check(const std::string &input);

    /**
     * Encodes raw bytes into a Base58 string.
     *
     * @param input the raw bytes to encode
     * @return the Base58-encoded string
     */
    [[nodiscard]] std::string encode(std::vector<uint8_t> input);

    /**
     * Encodes the contents of a deserializer into a Base58 string.
     *
     * @param reader the deserializer containing bytes to encode
     * @return the Base58-encoded string
     */
    [[nodiscard]] std::string encode(const Serialization::deserializer_t &reader);

    /**
     * Encodes the contents of a serializer into a Base58 string.
     *
     * @param writer the serializer containing bytes to encode
     * @return the Base58-encoded string
     */
    [[nodiscard]] std::string encode(const Serialization::serializer_t &writer);

    /**
     * Encodes raw bytes into a Base58 string with an appended checksum.
     *
     * The checksum allows the decoder to detect accidental corruption.
     *
     * @param input the raw bytes to encode
     * @return the Base58-encoded string with checksum
     */
    [[nodiscard]] std::string encode_check(const std::vector<uint8_t> &input);

    /**
     * Encodes the contents of a deserializer into a Base58 string with checksum.
     *
     * @param reader the deserializer containing bytes to encode
     * @return the Base58-encoded string with checksum
     */
    [[nodiscard]] std::string encode_check(const Serialization::deserializer_t &reader);

    /**
     * Encodes the contents of a serializer into a Base58 string with checksum.
     *
     * @param writer the serializer containing bytes to encode
     * @return the Base58-encoded string with checksum
     */
    [[nodiscard]] std::string encode_check(const Serialization::serializer_t &writer);
} // namespace Crypto::Base58

#endif // CRYPTO_BASE58_H
