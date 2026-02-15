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
 * @file crypto_frost_types.h
 * @brief All FROST threshold signature types: DKG shares, key packages, nonces, and signature shares.
 */

#ifndef CRYPTO_FROST_TYPES_H
#define CRYPTO_FROST_TYPES_H

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_point_vector_t.h>
#include <types/crypto_scalar_t.h>

/**
 * @brief A DKG secret share: participant identifier and share value.
 */
struct crypto_frost_secret_share_t final : Serializable
{
    crypto_frost_secret_share_t() = default;

    crypto_frost_secret_share_t(size_t identifier, const crypto_scalar_t &value);

    explicit crypto_frost_secret_share_t(Serialization::deserializer_t &reader);

    void deserialize(const std::vector<unsigned char> &data) override;

    void deserialize(Serialization::deserializer_t &reader) override;

    JSON_FROM_FUNC(fromJSON) override;

    JSON_FROM_KEY_FUNC(fromJSON) override;

    [[nodiscard]] crypto_hash_t hash() const;

    void serialize(Serialization::serializer_t &writer) const override;

    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    [[nodiscard]] size_t size() const override;

    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    [[nodiscard]] std::string to_string() const override;

    size_t identifier = 0;
    crypto_scalar_t value;
};

/**
 * @brief A participant's DKG result: signing share, verifying share, group public key.
 */
struct crypto_frost_key_package_t final : Serializable
{
    crypto_frost_key_package_t() = default;

    crypto_frost_key_package_t(
        size_t identifier,
        const crypto_scalar_t &signing_share,
        const crypto_point_t &verifying_share,
        const crypto_point_t &group_public_key,
        size_t min_signers);

    explicit crypto_frost_key_package_t(Serialization::deserializer_t &reader);

    void deserialize(const std::vector<unsigned char> &data) override;

    void deserialize(Serialization::deserializer_t &reader) override;

    JSON_FROM_FUNC(fromJSON) override;

    JSON_FROM_KEY_FUNC(fromJSON) override;

    [[nodiscard]] crypto_hash_t hash() const;

    void serialize(Serialization::serializer_t &writer) const override;

    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    [[nodiscard]] size_t size() const override;

    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    [[nodiscard]] std::string to_string() const override;

    size_t identifier = 0;
    crypto_scalar_t signing_share;
    crypto_point_t verifying_share;
    crypto_point_t group_public_key;
    size_t min_signers = 0;
};

/**
 * @brief Public info shared among all participants: group key and per-participant verifying shares.
 */
struct crypto_frost_public_key_package_t final : Serializable
{
    crypto_frost_public_key_package_t() = default;

    crypto_frost_public_key_package_t(
        const crypto_point_t &group_public_key,
        std::vector<std::pair<size_t, crypto_point_t>> verifying_shares);

    explicit crypto_frost_public_key_package_t(Serialization::deserializer_t &reader);

    void deserialize(const std::vector<unsigned char> &data) override;

    void deserialize(Serialization::deserializer_t &reader) override;

    JSON_FROM_FUNC(fromJSON) override;

    JSON_FROM_KEY_FUNC(fromJSON) override;

    [[nodiscard]] crypto_hash_t hash() const;

    void serialize(Serialization::serializer_t &writer) const override;

    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    [[nodiscard]] size_t size() const override;

    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    [[nodiscard]] std::string to_string() const override;

    crypto_point_t group_public_key;
    std::vector<std::pair<size_t, crypto_point_t>> verifying_shares;
};

/**
 * @brief Round 1 secret nonces (NOT serialized over the wire -- kept private by the signer).
 */
struct crypto_frost_nonce_t
{
    crypto_frost_nonce_t() = default;

    crypto_frost_nonce_t(const crypto_scalar_t &hiding_nonce, const crypto_scalar_t &binding_nonce);

    crypto_scalar_t hiding_nonce;
    crypto_scalar_t binding_nonce;
};

/**
 * @brief Round 1 public nonce commitments (sent to other participants).
 */
struct crypto_frost_nonce_commitment_t final : Serializable
{
    crypto_frost_nonce_commitment_t() = default;

    crypto_frost_nonce_commitment_t(
        size_t identifier,
        const crypto_point_t &hiding,
        const crypto_point_t &binding);

    explicit crypto_frost_nonce_commitment_t(Serialization::deserializer_t &reader);

    void deserialize(const std::vector<unsigned char> &data) override;

    void deserialize(Serialization::deserializer_t &reader) override;

    JSON_FROM_FUNC(fromJSON) override;

    JSON_FROM_KEY_FUNC(fromJSON) override;

    [[nodiscard]] crypto_hash_t hash() const;

    void serialize(Serialization::serializer_t &writer) const override;

    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    [[nodiscard]] size_t size() const override;

    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    [[nodiscard]] std::string to_string() const override;

    size_t identifier = 0;
    crypto_point_t hiding;
    crypto_point_t binding;
};

/**
 * @brief Round 2 signature share from a single participant.
 */
struct crypto_frost_signature_share_t final : Serializable
{
    crypto_frost_signature_share_t() = default;

    crypto_frost_signature_share_t(size_t identifier, const crypto_scalar_t &share);

    explicit crypto_frost_signature_share_t(Serialization::deserializer_t &reader);

    void deserialize(const std::vector<unsigned char> &data) override;

    void deserialize(Serialization::deserializer_t &reader) override;

    JSON_FROM_FUNC(fromJSON) override;

    JSON_FROM_KEY_FUNC(fromJSON) override;

    [[nodiscard]] crypto_hash_t hash() const;

    void serialize(Serialization::serializer_t &writer) const override;

    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    [[nodiscard]] size_t size() const override;

    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    [[nodiscard]] std::string to_string() const override;

    size_t identifier = 0;
    crypto_scalar_t share;
};

#endif
