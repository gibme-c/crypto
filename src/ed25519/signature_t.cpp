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
 * @file signature_t.cpp
 * @brief Ed25519 signature serialization as a (L, R) scalar pair.
 */

#include <ed25519/signature_t.h>
#include <helpers/debug_helper.h>
#include <utility>

signature_t::signature_t(std::initializer_list<unsigned char> _LR)
{
    auto data = std::vector<unsigned char>(_LR.begin(), _LR.end());

    deserialize(data);
}

signature_t::signature_t(const std::vector<unsigned char> &_LR)
{
    deserialize(_LR);
}

signature_t::signature_t(const std::string &_LR)
{
    from_string(_LR);
}

bool signature_t::operator==(const signature_t &other) const
{
    return LR.L == other.LR.L && LR.R == other.LR.R;
}

bool signature_t::operator!=(const signature_t &other) const
{
    return !(*this == other);
}

void signature_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        LR.L = reader.pod<scalar_t>();

        LR.R = reader.pod<scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize signature_t");
}

void signature_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

bool signature_t::empty() const
{
    return *this == signature_t();
}

void signature_t::fromJSON(const JSONValue &j)
{
    if (!j.IsString())
    {
        throw std::invalid_argument("JSON value is of the wrong type: " + JSON_TYPE_NAME);
    }

    from_string(j.GetString());
}

void signature_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

hash_t signature_t::hash() const
{
    const auto serialized = serialize();

    return hash_t::sha3(serialized);
}

void signature_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(LR.L);

    writer.pod(LR.R);
}

std::vector<unsigned char> signature_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t signature_t::size() const
{
    return LR.L.size() + LR.R.size();
}

void signature_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.String(to_string());
}

std::string signature_t::to_string() const
{
    auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}

void signature_t::from_string(const std::string &s)
{
    const auto input = Serialization::from_hex(s);

    Serialization::deserializer_t reader(input);

    deserialize(reader);
}
