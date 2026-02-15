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
// Based on ePrint 2022/510 (Bulletproofs++)

#include <types/crypto_bulletproof_pp_t.h>

crypto_bulletproof_pp_t::crypto_bulletproof_pp_t(
    const crypto_point_t &C_l,
    const crypto_point_t &C_r,
    const crypto_point_t &C_o,
    const crypto_point_t &C_s,
    const crypto_point_t &R,
    std::vector<crypto_point_t> X,
    std::vector<crypto_point_t> W,
    std::vector<crypto_scalar_t> l,
    std::vector<crypto_scalar_t> n):
    C_l(C_l), C_r(C_r), C_o(C_o), C_s(C_s), R(R),
    X(std::move(X)), W(std::move(W)), l(std::move(l)), n(std::move(n))
{
}

crypto_bulletproof_pp_t::crypto_bulletproof_pp_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

crypto_bulletproof_pp_t::crypto_bulletproof_pp_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

crypto_bulletproof_pp_t::crypto_bulletproof_pp_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

crypto_bulletproof_pp_t::crypto_bulletproof_pp_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

bool crypto_bulletproof_pp_t::check_construction() const
{
    if (X.size() != W.size() || X.empty())
    {
        return false;
    }

    if (l.empty() || n.empty())
    {
        return false;
    }

    if (!C_l.valid() || !C_r.valid() || !C_o.valid() || !C_s.valid() || !R.valid())
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

    for (const auto &point : W)
    {
        if (!point.valid())
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

void crypto_bulletproof_pp_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void crypto_bulletproof_pp_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        C_l = reader.pod<crypto_point_t>();

        C_r = reader.pod<crypto_point_t>();

        C_o = reader.pod<crypto_point_t>();

        C_s = reader.pod<crypto_point_t>();

        R = reader.pod<crypto_point_t>();

        X = reader.podV<crypto_point_t>();

        W = reader.podV<crypto_point_t>();

        l = reader.podV<crypto_scalar_t>();

        n = reader.podV<crypto_scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_bulletproof_pp_t");
}

void crypto_bulletproof_pp_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(C_l);

        LOAD_KEY_FROM_JSON(C_r);

        LOAD_KEY_FROM_JSON(C_o);

        LOAD_KEY_FROM_JSON(C_s);

        LOAD_KEY_FROM_JSON(R);

        LOAD_KEYV_FROM_JSON(X, crypto_point_t);

        LOAD_KEYV_FROM_JSON(W, crypto_point_t);

        LOAD_KEYV_FROM_JSON(l, crypto_scalar_t);

        LOAD_KEYV_FROM_JSON(n, crypto_scalar_t);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_bulletproof_pp_t");
}

void crypto_bulletproof_pp_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

crypto_hash_t crypto_bulletproof_pp_t::hash() const
{
    const auto serialized = serialize();

    return crypto_hash_t::sha3(serialized);
}

void crypto_bulletproof_pp_t::serialize(Serialization::serializer_t &writer) const
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

std::vector<unsigned char> crypto_bulletproof_pp_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t crypto_bulletproof_pp_t::size() const
{
    return serialize().size();
}

void crypto_bulletproof_pp_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
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

std::string crypto_bulletproof_pp_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
