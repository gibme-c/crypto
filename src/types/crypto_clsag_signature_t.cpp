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
//
// Inspired by the work of Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/clsag

#include <types/crypto_clsag_signature_t.h>

crypto_clsag_signature_t::crypto_clsag_signature_t(
    std::vector<crypto_scalar_t> scalars,
    const crypto_scalar_t &challenge,
    const crypto_key_image_t &commitment_image,
    const crypto_pedersen_commitment_t &pseudo_commitment):
    scalars(std::move(scalars)),
    challenge(challenge),
    commitment_image(commitment_image),
    pseudo_commitment(pseudo_commitment)
{
}

crypto_clsag_signature_t::crypto_clsag_signature_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

crypto_clsag_signature_t::crypto_clsag_signature_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

crypto_clsag_signature_t::crypto_clsag_signature_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

crypto_clsag_signature_t::crypto_clsag_signature_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

bool crypto_clsag_signature_t::check_construction(size_t ring_size, bool use_commitments) const
{
    if (scalars.size() != ring_size)
    {
        return false;
    }

    if (!challenge.valid())
    {
        return false;
    }

    for (const auto &scalar : scalars)
    {
        if (!scalar.valid())
        {
            return false;
        }
    }

    if (use_commitments && !commitment_image.check_subgroup())
    {
        return false;
    }

    return true;
}

void crypto_clsag_signature_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void crypto_clsag_signature_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        scalars = reader.podV<crypto_scalar_t>();

        challenge = reader.pod<crypto_scalar_t>();

        if (reader.boolean())
        {
            commitment_image = reader.pod<crypto_key_image_t>();

            pseudo_commitment = reader.pod<crypto_pedersen_commitment_t>();
        }
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_clsag_signature_t");
}

void crypto_clsag_signature_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEYV_FROM_JSON(scalars, crypto_scalar_t);

        LOAD_KEY_FROM_JSON(challenge);

        JSON_IF_MEMBER(commitment_image)
        LOAD_KEY_FROM_JSON(commitment_image);

        JSON_IF_MEMBER(pseudo_commitment)
        LOAD_KEY_FROM_JSON(pseudo_commitment);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_clsag_signature_t");
}

void crypto_clsag_signature_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

crypto_hash_t crypto_clsag_signature_t::hash() const
{
    const auto serialized = serialize();

    return crypto_hash_t::sha3(serialized);
}

void crypto_clsag_signature_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(scalars);

    writer.pod(challenge);

    if (commitment_image.valid())
    {
        writer.boolean(true);

        writer.pod(commitment_image);

        writer.pod(pseudo_commitment);
    }
    else
    {
        writer.boolean(false);
    }
}

std::vector<unsigned char> crypto_clsag_signature_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t crypto_clsag_signature_t::size() const
{
    return serialize().size();
}

void crypto_clsag_signature_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    {
        KEYV_TO_JSON(scalars);

        KEY_TO_JSON(challenge);

        if (commitment_image.valid())
        {
            KEY_TO_JSON(commitment_image);

            KEY_TO_JSON(pseudo_commitment);
        }
    }
    writer.EndObject();
}

std::string crypto_clsag_signature_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
