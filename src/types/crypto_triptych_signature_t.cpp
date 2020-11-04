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
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

#include <types/crypto_triptych_signature_t.h>

crypto_triptych_signature_t::crypto_triptych_signature_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

crypto_triptych_signature_t::crypto_triptych_signature_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

crypto_triptych_signature_t::crypto_triptych_signature_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

crypto_triptych_signature_t::crypto_triptych_signature_t(
    const crypto_key_image_t &commitment_image,
    const crypto_pedersen_commitment_t &pseudo_commitment,
    const crypto_point_t &A,
    const crypto_point_t &B,
    const crypto_point_t &C,
    const crypto_point_t &D,
    std::vector<crypto_point_t> X,
    std::vector<crypto_point_t> Y,
    std::vector<std::vector<crypto_scalar_t>> f,
    const crypto_scalar_t &zA,
    const crypto_scalar_t &zC,
    const crypto_scalar_t &z):
    commitment_image(commitment_image),
    pseudo_commitment(pseudo_commitment),
    A(A),
    B(B),
    C(C),
    D(D),
    X(std::move(X)),
    Y(std::move(Y)),
    f(std::move(f)),
    zA(zA),
    zC(zC),
    z(z)
{
}

crypto_triptych_signature_t::crypto_triptych_signature_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

bool crypto_triptych_signature_t::check_construction(size_t m, size_t n) const
{
    if (!A.valid() || !B.valid() || !C.valid() || !D.valid())
    {
        return false;
    }

    if (X.size() != m || Y.size() != m || f.size() != m)
    {
        return false;
    }

    for (const auto &point : X)
    {
        if (!point.valid())
        {
            return false;
        }
    }

    for (const auto &point : Y)
    {
        if (!point.valid())
        {
            return false;
        }
    }

    if (!zA.valid() || !zC.valid() || !z.valid())
    {
        return false;
    }

    for (const auto &level1 : f)
    {
        if (level1.size() != n - 1)
        {
            return false;
        }

        for (const auto &scalar : level1)
        {
            if (!scalar.valid())
            {
                return false;
            }
        }
    }

    if (!commitment_image.check_subgroup())
    {
        return false;
    }

    return true;
}

void crypto_triptych_signature_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void crypto_triptych_signature_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        A = reader.pod<crypto_point_t>();

        B = reader.pod<crypto_point_t>();

        C = reader.pod<crypto_point_t>();

        D = reader.pod<crypto_point_t>();

        X = reader.podV<crypto_point_t>();

        Y = reader.podV<crypto_point_t>();

        f = reader.podVV<crypto_scalar_t>();

        zA = reader.pod<crypto_scalar_t>();

        zC = reader.pod<crypto_scalar_t>();

        z = reader.pod<crypto_scalar_t>();

        commitment_image = reader.pod<crypto_key_image_t>();

        pseudo_commitment = reader.pod<crypto_pedersen_commitment_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_triptych_signature_t");
}

void crypto_triptych_signature_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(A);

        LOAD_KEY_FROM_JSON(B);

        LOAD_KEY_FROM_JSON(C);

        LOAD_KEY_FROM_JSON(D);

        LOAD_KEYV_FROM_JSON(X, crypto_point_t);

        LOAD_KEYV_FROM_JSON(Y, crypto_point_t);

        LOAD_KEYVV_FROM_JSON(f, crypto_scalar_t);

        LOAD_KEY_FROM_JSON(zA);

        LOAD_KEY_FROM_JSON(zC);

        LOAD_KEY_FROM_JSON(z);

        LOAD_KEY_FROM_JSON(commitment_image);

        LOAD_KEY_FROM_JSON(pseudo_commitment);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_triptych_signature_t");
}

void crypto_triptych_signature_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

crypto_hash_t crypto_triptych_signature_t::hash() const
{
    const auto serialized = serialize();

    return crypto_hash_t::sha3(serialized);
}

void crypto_triptych_signature_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(A);

    writer.pod(B);

    writer.pod(C);

    writer.pod(D);

    writer.pod(X);

    writer.pod(Y);

    writer.pod(f);

    writer.pod(zA);

    writer.pod(zC);

    writer.pod(z);

    writer.pod(commitment_image);

    writer.pod(pseudo_commitment);
}

std::vector<unsigned char> crypto_triptych_signature_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t crypto_triptych_signature_t::size() const
{
    return serialize().size();
}

void crypto_triptych_signature_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    {
        KEY_TO_JSON(A);

        KEY_TO_JSON(B);

        KEY_TO_JSON(C);

        KEY_TO_JSON(D);

        KEYV_TO_JSON(X);

        KEYV_TO_JSON(Y);

        KEYVV_TO_JSON(f);

        KEY_TO_JSON(zA);

        KEY_TO_JSON(zC);

        KEY_TO_JSON(z);

        KEY_TO_JSON(commitment_image);

        KEY_TO_JSON(pseudo_commitment);
    }
    writer.EndObject();
}

std::string crypto_triptych_signature_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
