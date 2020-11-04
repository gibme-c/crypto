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

#include <encoding/address_encoding.h>
#include <encoding/base58.h>
#include <encoding/cn_base58.h>
#include <serialization.h>

namespace Crypto::Address
{
    namespace Base58
    {
        std::tuple<bool, uint64_t, crypto_public_key_t, crypto_public_key_t> decode(const std::string &address)
        {
            auto [success, decoded] = Crypto::Base58::decode_check(address);

            if (!success)
            {
                return {success, 0, {}, {}};
            }

            try
            {
                const auto prefix = decoded.varint<uint64_t>();

                const auto public_spend = decoded.pod<crypto_public_key_t>();

                crypto_public_key_t public_view;

                if (decoded.unread_bytes() == public_view.size())
                {
                    public_view = decoded.pod<crypto_public_key_t>();
                }

                return {success, prefix, public_spend, public_view};
            }
            catch (...)
            {
                return {false, 0, {}, {}};
            }
        }

        std::string encode(const uint64_t &prefix, const crypto_public_key_t &public_key)
        {
            Serialization::serializer_t writer;

            writer.varint(prefix);

            writer.pod(public_key);

            return Crypto::Base58::encode_check(writer);
        }

        std::string encode(
            const uint64_t &prefix,
            const crypto_public_key_t &public_spend,
            const crypto_public_key_t &public_view)
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
        std::tuple<bool, uint64_t, crypto_public_key_t, crypto_public_key_t> decode(const std::string &address)
        {
            auto [success, decoded] = Crypto::CNBase58::decode_check(address);

            if (!success)
            {
                return {success, 0, {}, {}};
            }

            try
            {
                const auto prefix = decoded.varint<uint64_t>();

                const auto public_spend = decoded.pod<crypto_public_key_t>();

                crypto_public_key_t public_view;

                if (decoded.unread_bytes() == public_view.size())
                {
                    public_view = decoded.pod<crypto_public_key_t>();
                }

                return {success, prefix, public_spend, public_view};
            }
            catch (...)
            {
                return {false, 0, {}, {}};
            }
        }

        std::string encode(const uint64_t &prefix, const crypto_public_key_t &public_key)
        {
            Serialization::serializer_t writer;

            writer.varint(prefix);

            writer.pod(public_key);

            return Crypto::CNBase58::encode_check(writer);
        }

        std::string encode(
            const uint64_t &prefix,
            const crypto_public_key_t &public_spend,
            const crypto_public_key_t &public_view)
        {
            Serialization::serializer_t writer;

            writer.varint(prefix);

            writer.pod(public_spend);

            writer.pod(public_view);

            return Crypto::CNBase58::encode_check(writer);
        }
    } // namespace CNBase58
} // namespace Crypto::Address
