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
 * @file crypto_frost_types.cpp
 * @brief FROST type serialization and deserialization.
 */

#include <types/crypto_frost_types.h>

// ===== crypto_frost_secret_share_t =====

crypto_frost_secret_share_t::crypto_frost_secret_share_t(size_t identifier, const crypto_scalar_t &value):
    identifier(identifier), value(value)
{
}

crypto_frost_secret_share_t::crypto_frost_secret_share_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

void crypto_frost_secret_share_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);
    deserialize(reader);
}

void crypto_frost_secret_share_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        identifier = reader.varint<size_t>();
        value = reader.pod<crypto_scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_secret_share_t");
}

void crypto_frost_secret_share_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();
        LOAD_U64_FROM_JSON(identifier);
        LOAD_KEY_FROM_JSON(value);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_secret_share_t");
}

void crypto_frost_secret_share_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    fromJSON(get_json_value(val, key));
}

crypto_hash_t crypto_frost_secret_share_t::hash() const
{
    return crypto_hash_t::sha3(serialize());
}

void crypto_frost_secret_share_t::serialize(Serialization::serializer_t &writer) const
{
    writer.varint(identifier);
    writer.pod(value);
}

std::vector<unsigned char> crypto_frost_secret_share_t::serialize() const
{
    Serialization::serializer_t writer;
    serialize(writer);
    return writer.vector();
}

size_t crypto_frost_secret_share_t::size() const { return serialize().size(); }

void crypto_frost_secret_share_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    U64_TO_JSON(identifier);
    KEY_TO_JSON(value);
    writer.EndObject();
}

std::string crypto_frost_secret_share_t::to_string() const
{
    const auto bytes = serialize();
    return Serialization::to_hex(bytes.data(), bytes.size());
}

// ===== crypto_frost_key_package_t =====

crypto_frost_key_package_t::crypto_frost_key_package_t(
    size_t identifier,
    const crypto_scalar_t &signing_share,
    const crypto_point_t &verifying_share,
    const crypto_point_t &group_public_key,
    size_t min_signers):
    identifier(identifier),
    signing_share(signing_share),
    verifying_share(verifying_share),
    group_public_key(group_public_key),
    min_signers(min_signers)
{
}

crypto_frost_key_package_t::crypto_frost_key_package_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

void crypto_frost_key_package_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);
    deserialize(reader);
}

void crypto_frost_key_package_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        identifier = reader.varint<size_t>();
        signing_share = reader.pod<crypto_scalar_t>();
        verifying_share = reader.pod<crypto_point_t>();
        group_public_key = reader.pod<crypto_point_t>();
        min_signers = reader.varint<size_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_key_package_t");
}

void crypto_frost_key_package_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();
        LOAD_U64_FROM_JSON(identifier);
        LOAD_KEY_FROM_JSON(signing_share);
        LOAD_KEY_FROM_JSON(verifying_share);
        LOAD_KEY_FROM_JSON(group_public_key);
        LOAD_U64_FROM_JSON(min_signers);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_key_package_t");
}

void crypto_frost_key_package_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    fromJSON(get_json_value(val, key));
}

crypto_hash_t crypto_frost_key_package_t::hash() const
{
    return crypto_hash_t::sha3(serialize());
}

void crypto_frost_key_package_t::serialize(Serialization::serializer_t &writer) const
{
    writer.varint(identifier);
    writer.pod(signing_share);
    writer.pod(verifying_share);
    writer.pod(group_public_key);
    writer.varint(min_signers);
}

std::vector<unsigned char> crypto_frost_key_package_t::serialize() const
{
    Serialization::serializer_t writer;
    serialize(writer);
    return writer.vector();
}

size_t crypto_frost_key_package_t::size() const { return serialize().size(); }

void crypto_frost_key_package_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    U64_TO_JSON(identifier);
    KEY_TO_JSON(signing_share);
    KEY_TO_JSON(verifying_share);
    KEY_TO_JSON(group_public_key);
    U64_TO_JSON(min_signers);
    writer.EndObject();
}

std::string crypto_frost_key_package_t::to_string() const
{
    const auto bytes = serialize();
    return Serialization::to_hex(bytes.data(), bytes.size());
}

// ===== crypto_frost_public_key_package_t =====

crypto_frost_public_key_package_t::crypto_frost_public_key_package_t(
    const crypto_point_t &group_public_key,
    std::vector<std::pair<size_t, crypto_point_t>> verifying_shares):
    group_public_key(group_public_key), verifying_shares(std::move(verifying_shares))
{
}

crypto_frost_public_key_package_t::crypto_frost_public_key_package_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

void crypto_frost_public_key_package_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);
    deserialize(reader);
}

void crypto_frost_public_key_package_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        group_public_key = reader.pod<crypto_point_t>();
        const auto count = reader.varint<size_t>();
        verifying_shares.clear();
        verifying_shares.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            auto id = reader.varint<size_t>();
            auto pt = reader.pod<crypto_point_t>();
            verifying_shares.emplace_back(id, pt);
        }
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_public_key_package_t");
}

void crypto_frost_public_key_package_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();
        LOAD_KEY_FROM_JSON(group_public_key);
        // verifying_shares as array of {identifier, point} objects
        if (!has_member(j, "verifying_shares"))
            throw std::invalid_argument("verifying_shares not found");
        const auto &arr = get_json_value(j, "verifying_shares");
        if (!arr.IsArray())
            throw std::invalid_argument("verifying_shares must be array");
        verifying_shares.clear();
        for (rapidjson::SizeType i = 0; i < arr.Size(); ++i)
        {
            const auto &elem = arr[i];
            if (!elem.IsObject() || !elem.HasMember("identifier") || !elem.HasMember("point"))
                throw std::invalid_argument("Invalid verifying_shares element");
            const size_t id = elem["identifier"].GetUint64();
            crypto_point_t pt;
            pt.fromJSON(elem, "point");
            verifying_shares.emplace_back(id, pt);
        }
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_public_key_package_t");
}

void crypto_frost_public_key_package_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    fromJSON(get_json_value(val, key));
}

crypto_hash_t crypto_frost_public_key_package_t::hash() const
{
    return crypto_hash_t::sha3(serialize());
}

void crypto_frost_public_key_package_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(group_public_key);
    writer.varint(verifying_shares.size());
    for (const auto &[id, pt] : verifying_shares)
    {
        writer.varint(id);
        writer.pod(pt);
    }
}

std::vector<unsigned char> crypto_frost_public_key_package_t::serialize() const
{
    Serialization::serializer_t writer;
    serialize(writer);
    return writer.vector();
}

size_t crypto_frost_public_key_package_t::size() const { return serialize().size(); }

void crypto_frost_public_key_package_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    KEY_TO_JSON(group_public_key);
    writer.Key("verifying_shares");
    writer.StartArray();
    for (const auto &[id, pt] : verifying_shares)
    {
        writer.StartObject();
        writer.Key("identifier");
        writer.Uint64(id);
        writer.Key("point");
        pt.toJSON(writer);
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
}

std::string crypto_frost_public_key_package_t::to_string() const
{
    const auto bytes = serialize();
    return Serialization::to_hex(bytes.data(), bytes.size());
}

// ===== crypto_frost_nonce_t =====

crypto_frost_nonce_t::crypto_frost_nonce_t(
    const crypto_scalar_t &hiding_nonce,
    const crypto_scalar_t &binding_nonce):
    hiding_nonce(hiding_nonce), binding_nonce(binding_nonce)
{
}

// ===== crypto_frost_nonce_commitment_t =====

crypto_frost_nonce_commitment_t::crypto_frost_nonce_commitment_t(
    size_t identifier,
    const crypto_point_t &hiding,
    const crypto_point_t &binding):
    identifier(identifier), hiding(hiding), binding(binding)
{
}

crypto_frost_nonce_commitment_t::crypto_frost_nonce_commitment_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

void crypto_frost_nonce_commitment_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);
    deserialize(reader);
}

void crypto_frost_nonce_commitment_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        identifier = reader.varint<size_t>();
        hiding = reader.pod<crypto_point_t>();
        binding = reader.pod<crypto_point_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_nonce_commitment_t");
}

void crypto_frost_nonce_commitment_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();
        LOAD_U64_FROM_JSON(identifier);
        LOAD_KEY_FROM_JSON(hiding);
        LOAD_KEY_FROM_JSON(binding);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_nonce_commitment_t");
}

void crypto_frost_nonce_commitment_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    fromJSON(get_json_value(val, key));
}

crypto_hash_t crypto_frost_nonce_commitment_t::hash() const
{
    return crypto_hash_t::sha3(serialize());
}

void crypto_frost_nonce_commitment_t::serialize(Serialization::serializer_t &writer) const
{
    writer.varint(identifier);
    writer.pod(hiding);
    writer.pod(binding);
}

std::vector<unsigned char> crypto_frost_nonce_commitment_t::serialize() const
{
    Serialization::serializer_t writer;
    serialize(writer);
    return writer.vector();
}

size_t crypto_frost_nonce_commitment_t::size() const { return serialize().size(); }

void crypto_frost_nonce_commitment_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    U64_TO_JSON(identifier);
    KEY_TO_JSON(hiding);
    KEY_TO_JSON(binding);
    writer.EndObject();
}

std::string crypto_frost_nonce_commitment_t::to_string() const
{
    const auto bytes = serialize();
    return Serialization::to_hex(bytes.data(), bytes.size());
}

// ===== crypto_frost_signature_share_t =====

crypto_frost_signature_share_t::crypto_frost_signature_share_t(size_t identifier, const crypto_scalar_t &share):
    identifier(identifier), share(share)
{
}

crypto_frost_signature_share_t::crypto_frost_signature_share_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

void crypto_frost_signature_share_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);
    deserialize(reader);
}

void crypto_frost_signature_share_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        identifier = reader.varint<size_t>();
        share = reader.pod<crypto_scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_signature_share_t");
}

void crypto_frost_signature_share_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();
        LOAD_U64_FROM_JSON(identifier);
        LOAD_KEY_FROM_JSON(share);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_frost_signature_share_t");
}

void crypto_frost_signature_share_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    fromJSON(get_json_value(val, key));
}

crypto_hash_t crypto_frost_signature_share_t::hash() const
{
    return crypto_hash_t::sha3(serialize());
}

void crypto_frost_signature_share_t::serialize(Serialization::serializer_t &writer) const
{
    writer.varint(identifier);
    writer.pod(share);
}

std::vector<unsigned char> crypto_frost_signature_share_t::serialize() const
{
    Serialization::serializer_t writer;
    serialize(writer);
    return writer.vector();
}

size_t crypto_frost_signature_share_t::size() const { return serialize().size(); }

void crypto_frost_signature_share_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    U64_TO_JSON(identifier);
    KEY_TO_JSON(share);
    writer.EndObject();
}

std::string crypto_frost_signature_share_t::to_string() const
{
    const auto bytes = serialize();
    return Serialization::to_hex(bytes.data(), bytes.size());
}
