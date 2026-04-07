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
// Based on ePrint 2022/510 (Bulletproofs++)

/**
 * @file bulletproof_pp_t.cpp
 * @brief Bulletproof++ range proof serialization, deserialization, and construction validation.
 */

#include <bulletproofspp/bulletproof_pp_t.h>
#include <helpers/debug_helper.h>

bulletproof_pp_t::bulletproof_pp_t(
    const point_t &_C_l,
    const point_t &_C_r,
    const point_t &_C_o,
    const point_t &_C_s,
    const point_t &_R,
    std::vector<point_t> _X,
    std::vector<point_t> _W,
    std::vector<scalar_t> _l,
    std::vector<scalar_t> _n):
    C_l(_C_l),
    C_r(_C_r),
    C_o(_C_o),
    C_s(_C_s),
    R(_R),
    X(std::move(_X)),
    W(std::move(_W)),
    l(std::move(_l)),
    n(std::move(_n))
{
}

bulletproof_pp_t::bulletproof_pp_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

bulletproof_pp_t::bulletproof_pp_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

bulletproof_pp_t::bulletproof_pp_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

bulletproof_pp_t::bulletproof_pp_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

bool bulletproof_pp_t::check_construction() const
{
    if (X.size() != W.size() || X.size() < 4)
    {
        return false;
    }

    if (l.size() != 2 || n.size() != 1)
    {
        return false;
    }

    // Every prover-supplied point must live in the prime-order subgroup. BP++'s
    // soundness proof is stated in E[l]; the verifier operates on these points
    // without cofactor-clearing them as group elements before the final MSM.
    // (The apparent "*8" in the verifier's MSM coefficients is scalar-field
    // multiplication mod L, not a point-level cofactor-clearing operation.)
    // check_subgroup() subsumes the curve-membership check provided by .valid().
    if (!C_l.check_subgroup() || !C_r.check_subgroup() || !C_o.check_subgroup() || !C_s.check_subgroup()
        || !R.check_subgroup())
    {
        return false;
    }

    for (const auto &point : X)
    {
        if (!point.check_subgroup())
        {
            return false;
        }
    }

    for (const auto &point : W)
    {
        if (!point.check_subgroup())
        {
            return false;
        }
    }

    for (const auto &scalar : l)
    {
        if (!scalar.valid())
        {
            return false;
        }
    }

    for (const auto &scalar : n)
    {
        if (!scalar.valid())
        {
            return false;
        }
    }

    return true;
}

void bulletproof_pp_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void bulletproof_pp_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        C_l = reader.pod<point_t>();

        C_r = reader.pod<point_t>();

        C_o = reader.pod<point_t>();

        C_s = reader.pod<point_t>();

        R = reader.pod<point_t>();

        X = reader.podV<point_t>();

        W = reader.podV<point_t>();

        l = reader.podV<scalar_t>();

        n = reader.podV<scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize bulletproof_pp_t");
}

void bulletproof_pp_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(C_l);

        LOAD_KEY_FROM_JSON(C_r);

        LOAD_KEY_FROM_JSON(C_o);

        LOAD_KEY_FROM_JSON(C_s);

        LOAD_KEY_FROM_JSON(R);

        LOAD_KEYV_FROM_JSON(X, point_t);

        LOAD_KEYV_FROM_JSON(W, point_t);

        LOAD_KEYV_FROM_JSON(l, scalar_t);

        LOAD_KEYV_FROM_JSON(n, scalar_t);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize bulletproof_pp_t");
}

void bulletproof_pp_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

hash_t bulletproof_pp_t::hash() const
{
    const auto serialized = serialize();

    return hash_t::sha3(serialized);
}

void bulletproof_pp_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(C_l);

    writer.pod(C_r);

    writer.pod(C_o);

    writer.pod(C_s);

    writer.pod(R);

    writer.pod(X);

    writer.pod(W);

    writer.pod(l);

    writer.pod(n);
}

std::vector<unsigned char> bulletproof_pp_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t bulletproof_pp_t::size() const
{
    return serialize().size();
}

void bulletproof_pp_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();
    {
        KEY_TO_JSON(C_l);

        KEY_TO_JSON(C_r);

        KEY_TO_JSON(C_o);

        KEY_TO_JSON(C_s);

        KEY_TO_JSON(R);

        KEYV_TO_JSON(X);

        KEYV_TO_JSON(W);

        KEYV_TO_JSON(l);

        KEYV_TO_JSON(n);
    }
    writer.EndObject();
}

std::string bulletproof_pp_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
