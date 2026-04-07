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
 * @file adapter_signature_t.cpp
 * @brief Adapter pre-signature serialization and deserialization.
 */

#include <adapter_signature/adapter_signature_t.h>
#include <helpers/debug_helper.h>

adapter_signature_t::adapter_signature_t(
    const point_t &_adapted_nonce,
    const scalar_t &_s_prime,
    const point_t &_nonce_commitment,
    const dleq_proof_t &_dleq):
    adapted_nonce(_adapted_nonce), s_prime(_s_prime), nonce_commitment(_nonce_commitment), dleq(_dleq)
{
}

adapter_signature_t::adapter_signature_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

adapter_signature_t::adapter_signature_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

adapter_signature_t::adapter_signature_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

adapter_signature_t::adapter_signature_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

void adapter_signature_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void adapter_signature_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        adapted_nonce = reader.pod<point_t>();

        s_prime = reader.pod<scalar_t>();

        nonce_commitment = reader.pod<point_t>();

        dleq.deserialize(reader);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize adapter_signature_t");
}

void adapter_signature_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(adapted_nonce);

        LOAD_KEY_FROM_JSON(s_prime);

        LOAD_KEY_FROM_JSON(nonce_commitment);

        LOAD_KEY_FROM_JSON(dleq);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize adapter_signature_t");
}

void adapter_signature_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

hash_t adapter_signature_t::hash() const
{
    const auto serialized = serialize();

    return hash_t::sha3(serialized);
}

void adapter_signature_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(adapted_nonce);

    writer.pod(s_prime);

    writer.pod(nonce_commitment);

    dleq.serialize(writer);
}

std::vector<unsigned char> adapter_signature_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t adapter_signature_t::size() const
{
    return serialize().size();
}

void adapter_signature_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    {
        KEY_TO_JSON(adapted_nonce);

        KEY_TO_JSON(s_prime);

        KEY_TO_JSON(nonce_commitment);

        KEY_TO_JSON(dleq);
    }
    writer.EndObject();
}

std::string adapter_signature_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
