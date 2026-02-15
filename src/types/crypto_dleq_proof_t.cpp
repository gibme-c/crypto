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
 * @file crypto_dleq_proof_t.cpp
 * @brief DLEQ proof serialization, deserialization, and construction.
 */

#include <types/crypto_dleq_proof_t.h>

crypto_dleq_proof_t::crypto_dleq_proof_t(const crypto_scalar_t &c, const crypto_scalar_t &s): c(c), s(s) {}

crypto_dleq_proof_t::crypto_dleq_proof_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

crypto_dleq_proof_t::crypto_dleq_proof_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

crypto_dleq_proof_t::crypto_dleq_proof_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

crypto_dleq_proof_t::crypto_dleq_proof_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

void crypto_dleq_proof_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void crypto_dleq_proof_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        c = reader.pod<crypto_scalar_t>();

        s = reader.pod<crypto_scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_dleq_proof_t");
}

void crypto_dleq_proof_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(c);

        LOAD_KEY_FROM_JSON(s);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_dleq_proof_t");
}

void crypto_dleq_proof_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

crypto_hash_t crypto_dleq_proof_t::hash() const
{
    const auto serialized = serialize();

    return crypto_hash_t::sha3(serialized);
}

void crypto_dleq_proof_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(c);

    writer.pod(s);
}

std::vector<unsigned char> crypto_dleq_proof_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t crypto_dleq_proof_t::size() const
{
    return serialize().size();
}

void crypto_dleq_proof_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    {
        KEY_TO_JSON(c);

        KEY_TO_JSON(s);
    }
    writer.EndObject();
}

std::string crypto_dleq_proof_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
