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
//
// Inspired by the work of Sarang Noether at
// https://github.com/SarangNoether/skunkworks/tree/pybullet-plus

/**
 * @file bulletproof_plus_t.cpp
 * @brief Bulletproof+ range proof serialization, deserialization, and construction validation.
 */

#include <helpers/debug_helper.h>
#include <bulletproofsplus/bulletproof_plus_t.h>

bulletproof_plus_t::bulletproof_plus_t(
    const point_t &_A,
    const point_t &_A1,
    const point_t &_B,
    const scalar_t &_r1,
    const scalar_t &_s1,
    const scalar_t &_d1,
    std::vector<point_t> _L,
    std::vector<point_t> _R):
    A(_A), A1(_A1), B(_B), r1(_r1), s1(_s1), d1(_d1), L(std::move(_L)), R(std::move(_R))
{
}

bulletproof_plus_t::bulletproof_plus_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

bulletproof_plus_t::bulletproof_plus_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

bulletproof_plus_t::bulletproof_plus_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

bulletproof_plus_t::bulletproof_plus_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

bool bulletproof_plus_t::check_construction() const
{
    if (L.size() != R.size() || L.empty())
    {
        return false;
    }

    if (!A.valid() || !A1.valid() || !B.valid())
    {
        return false;
    }

    for (const auto &point : L)
    {
        if (!point.valid())
        {
            return false;
        }
    }

    for (const auto &point : R)
    {
        if (!point.valid())
        {
            return false;
        }
    }

    if (!r1.valid() || !s1.valid() || !d1.valid())
    {
        return false;
    }

    return true;
}

void bulletproof_plus_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void bulletproof_plus_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        A = reader.pod<point_t>();

        A1 = reader.pod<point_t>();

        B = reader.pod<point_t>();

        r1 = reader.pod<scalar_t>();

        s1 = reader.pod<scalar_t>();

        d1 = reader.pod<scalar_t>();

        L = reader.podV<point_t>();

        R = reader.podV<point_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize bulletproof_plus_t");
}

void bulletproof_plus_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(A);

        LOAD_KEY_FROM_JSON(A1);

        LOAD_KEY_FROM_JSON(B);

        LOAD_KEY_FROM_JSON(r1);

        LOAD_KEY_FROM_JSON(s1);

        LOAD_KEY_FROM_JSON(d1);

        LOAD_KEYV_FROM_JSON(L, point_t);

        LOAD_KEYV_FROM_JSON(R, point_t);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize bulletproof_plus_t");
}

void bulletproof_plus_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

hash_t bulletproof_plus_t::hash() const
{
    const auto serialized = serialize();

    return hash_t::sha3(serialized);
}

void bulletproof_plus_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(A);

    writer.pod(A1);

    writer.pod(B);

    writer.pod(r1);

    writer.pod(s1);

    writer.pod(d1);

    writer.pod(L);

    writer.pod(R);
}

std::vector<unsigned char> bulletproof_plus_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t bulletproof_plus_t::size() const
{
    return serialize().size();
}

void bulletproof_plus_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    {
        KEY_TO_JSON(A);

        KEY_TO_JSON(A1);

        KEY_TO_JSON(B);

        KEY_TO_JSON(r1);

        KEY_TO_JSON(s1);

        KEY_TO_JSON(d1);

        KEYV_TO_JSON(L);

        KEYV_TO_JSON(R);
    }
    writer.EndObject();
}

std::string bulletproof_plus_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
