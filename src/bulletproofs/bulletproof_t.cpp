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
// https://github.com/SarangNoether/skunkworks/tree/pybullet

/**
 * @file bulletproof_t.cpp
 * @brief Bulletproof range proof serialization, deserialization, and construction validation.
 */

#include <bulletproofs/bulletproof_t.h>
#include <helpers/debug_helper.h>

bulletproof_t::bulletproof_t(
    const point_t &_A,
    const point_t &_S,
    const point_t &_T1,
    const point_t &_T2,
    const scalar_t &_taux,
    const scalar_t &_mu,
    std::vector<point_t> _L,
    std::vector<point_t> _R,
    const scalar_t &_g,
    const scalar_t &_h,
    const scalar_t &_t):
    A(_A), S(_S), T1(_T1), T2(_T2), taux(_taux), mu(_mu), L(std::move(_L)), R(std::move(_R)), g(_g), h(_h), t(_t)
{
}

bulletproof_t::bulletproof_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

bulletproof_t::bulletproof_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

bulletproof_t::bulletproof_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

bulletproof_t::bulletproof_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

bool bulletproof_t::check_construction() const
{
    if (L.size() != R.size() || L.empty())
    {
        return false;
    }

    if (!A.valid() || !S.valid() || !T1.valid() || !T2.valid())
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

    if (!taux.valid() || !mu.valid() || !g.valid() || !h.valid() || !t.valid())
    {
        return false;
    }

    return true;
}

void bulletproof_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void bulletproof_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        A = reader.pod<point_t>();

        S = reader.pod<point_t>();

        T1 = reader.pod<point_t>();

        T2 = reader.pod<point_t>();

        taux = reader.pod<scalar_t>();

        mu = reader.pod<scalar_t>();

        L = reader.podV<point_t>();

        R = reader.podV<point_t>();

        g = reader.pod<scalar_t>();

        h = reader.pod<scalar_t>();

        t = reader.pod<scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize bulletproof_t");
}

void bulletproof_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(A);

        LOAD_KEY_FROM_JSON(S);

        LOAD_KEY_FROM_JSON(T1);

        LOAD_KEY_FROM_JSON(T2);

        LOAD_KEY_FROM_JSON(taux);

        LOAD_KEY_FROM_JSON(mu);

        LOAD_KEYV_FROM_JSON(L, point_t);

        LOAD_KEYV_FROM_JSON(R, point_t);

        LOAD_KEY_FROM_JSON(g);

        LOAD_KEY_FROM_JSON(h);

        LOAD_KEY_FROM_JSON(t);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize bulletproof_t");
}

void bulletproof_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

hash_t bulletproof_t::hash() const
{
    const auto serialized = serialize();

    return hash_t::sha3(serialized);
}

void bulletproof_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(A);

    writer.pod(S);

    writer.pod(T1);

    writer.pod(T2);

    writer.pod(taux);

    writer.pod(mu);

    writer.pod(L);

    writer.pod(R);

    writer.pod(g);

    writer.pod(h);

    writer.pod(t);
}

std::vector<unsigned char> bulletproof_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t bulletproof_t::size() const
{
    return serialize().size();
}

void bulletproof_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    {
        KEY_TO_JSON(A);

        KEY_TO_JSON(S);

        KEY_TO_JSON(T1);

        KEY_TO_JSON(T2);

        KEY_TO_JSON(taux);

        KEY_TO_JSON(mu);

        KEYV_TO_JSON(L);

        KEYV_TO_JSON(R);

        KEY_TO_JSON(g);

        KEY_TO_JSON(h);

        KEY_TO_JSON(t);
    }
    writer.EndObject();
}

std::string bulletproof_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
