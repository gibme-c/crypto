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

#include <types/crypto_signature_t.h>
#include <utility>

crypto_signature_t::crypto_signature_t(std::initializer_list<unsigned char> LR)
{
    auto data = std::vector<unsigned char>(LR.begin(), LR.end());

    deserialize(data);
}

crypto_signature_t::crypto_signature_t(const std::vector<unsigned char> &LR)
{
    deserialize(LR);
}

crypto_signature_t::crypto_signature_t(const std::string &LR)
{
    from_string(LR);
}

bool crypto_signature_t::operator==(const crypto_signature_t &other) const
{
    return LR.L == other.LR.L && LR.R == other.LR.R;
}

bool crypto_signature_t::operator!=(const crypto_signature_t &other) const
{
    return !(*this == other);
}

void crypto_signature_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        LR.L = reader.pod<crypto_scalar_t>();

        LR.R = reader.pod<crypto_scalar_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize crypto_signature_t");
}

void crypto_signature_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

bool crypto_signature_t::empty() const
{
    return *this == crypto_signature_t();
}

void crypto_signature_t::fromJSON(const JSONValue &j)
{
    if (!j.IsString())
    {
        throw std::invalid_argument("JSON value is of the wrong type: " + JSON_TYPE_NAME);
    }

    from_string(j.GetString());
}

void crypto_signature_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

crypto_hash_t crypto_signature_t::hash() const
{
    const auto serialized = serialize();

    return crypto_hash_t::sha3(serialized);
}

void crypto_signature_t::serialize(Serialization::serializer_t &writer) const
{
    writer.pod(LR.L);

    writer.pod(LR.R);
}

std::vector<unsigned char> crypto_signature_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t crypto_signature_t::size() const
{
    return LR.L.size() + LR.R.size();
}

void crypto_signature_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.String(to_string());
}

std::string crypto_signature_t::to_string() const
{
    auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}

void crypto_signature_t::from_string(const std::string &s)
{
    const auto input = Serialization::from_hex(s);

    Serialization::deserializer_t reader(input);

    deserialize(reader);
}
