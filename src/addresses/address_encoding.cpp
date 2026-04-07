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
 * @file address_encoding.cpp
 * @brief Checksummed address encoding/decoding via both standard Base58 and CryptoNote Base58.
 */

#include <addresses/address_encoding.h>
#include <base58/base58.h>
#include <base58/cn_base58.h>
#include <serialization.h>

namespace Crypto::Address
{
    namespace
    {
        // Shared payload parser for both Base58 and CNBase58 decoders. The two namespaces
        // differ only in their checksum/encoding scheme; once decode_check has handed back a
        // verified deserializer, the {prefix, spend, optional view} layout is identical, and
        // so is the strict tail-length policy below. Keeping this in one place makes the
        // security-critical strict-tail check a single source of truth — any future tweak
        // lands here, not in two near-duplicates.
        std::tuple<bool, uint64_t, public_key_t, public_key_t>
            parse_address_payload(Serialization::deserializer_t &decoded)
        {
            try
            {
                const auto prefix = decoded.varint<uint64_t>();

                const auto public_spend = decoded.pod<public_key_t>();

                public_key_t public_view;

                const auto tail = decoded.unread_bytes();

                if (tail == public_view.size())
                {
                    public_view = decoded.pod<public_key_t>();
                }
                else if (tail != 0)
                {
                    // The only legal tail layouts after {prefix, public_spend} are exactly
                    // 0 bytes (single-key) or exactly public_key_t::size() bytes (dual-key).
                    // Anything else is ambiguous; fail closed rather than coercing the
                    // remainder into a zero view key. See include/addresses/README.md
                    // "Decoder strictness".
                    return {false, 0, {}, {}};
                }

                return {true, prefix, public_spend, public_view};
            }
            catch (const std::exception &)
            {
                return {false, 0, {}, {}};
            }
        }
    } // namespace

    namespace Base58
    {
        std::tuple<bool, uint64_t, public_key_t, public_key_t> decode(const std::string &address)
        {
            auto [success, decoded] = Crypto::Base58::decode_check(address);

            if (!success)
            {
                return {success, 0, {}, {}};
            }

            return parse_address_payload(decoded);
        }

        std::string encode(const uint64_t &prefix, const public_key_t &public_key)
        {
            Serialization::serializer_t writer;

            writer.varint(prefix);

            writer.pod(public_key);

            return Crypto::Base58::encode_check(writer);
        }

        std::string encode(const uint64_t &prefix, const public_key_t &public_spend, const public_key_t &public_view)
        {
            Serialization::serializer_t writer;

            writer.varint(prefix);

            writer.pod(public_spend);

            writer.pod(public_view);

            return Crypto::Base58::encode_check(writer);
        }
    } // namespace Base58

    namespace CNBase58
    {
        std::tuple<bool, uint64_t, public_key_t, public_key_t> decode(const std::string &address)
        {
            auto [success, decoded] = Crypto::CNBase58::decode_check(address);

            if (!success)
            {
                return {success, 0, {}, {}};
            }

            return parse_address_payload(decoded);
        }

        std::string encode(const uint64_t &prefix, const public_key_t &public_key)
        {
            Serialization::serializer_t writer;

            writer.varint(prefix);

            writer.pod(public_key);

            return Crypto::CNBase58::encode_check(writer);
        }

        std::string encode(const uint64_t &prefix, const public_key_t &public_spend, const public_key_t &public_view)
        {
            Serialization::serializer_t writer;

            writer.varint(prefix);

            writer.pod(public_spend);

            writer.pod(public_view);

            return Crypto::CNBase58::encode_check(writer);
        }
    } // namespace CNBase58
} // namespace Crypto::Address
