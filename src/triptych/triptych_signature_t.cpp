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
// Adapted from Python code by Sarang Noether found at
// https://github.com/SarangNoether/skunkworks/tree/triptych

/**
 * @file triptych_signature_t.cpp
 * @brief Triptych signature serialization, deserialization, and construction validation.
 */

#include <helpers/debug_helper.h>
#include <triptych/triptych_signature_t.h>

triptych_signature_t::triptych_signature_t(std::initializer_list<unsigned char> input)
{
    std::vector<unsigned char> data(input);

    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

triptych_signature_t::triptych_signature_t(const std::vector<unsigned char> &input)
{
    Serialization::deserializer_t reader(input);

    deserialize(reader);
}

triptych_signature_t::triptych_signature_t(const std::string &input)
{
    const auto string = Serialization::from_hex(input);

    Serialization::deserializer_t reader(string);

    deserialize(reader);
}

triptych_signature_t::triptych_signature_t(
    const key_image_t &_commitment_image,
    const pedersen_commitment_t &_pseudo_commitment,
    const point_t &_A,
    const point_t &_B,
    const point_t &_C,
    const point_t &_D,
    std::vector<point_t> _X,
    std::vector<point_t> _Y,
    std::vector<std::vector<scalar_t>> _f,
    const scalar_t &_zA,
    const scalar_t &_zC,
    const scalar_t &_z):
    commitment_image(_commitment_image),
    pseudo_commitment(_pseudo_commitment),
    A(_A),
    B(_B),
    C(_C),
    D(_D),
    X(std::move(_X)),
    Y(std::move(_Y)),
    f(std::move(_f)),
    zA(_zA),
    zC(_zC),
    z(_z)
{
}

triptych_signature_t::triptych_signature_t(Serialization::deserializer_t &reader)
{
    deserialize(reader);
}

bool triptych_signature_t::check_construction(size_t m, size_t n) const
{
    // The four commitment-tensor points feed the MSM identity check at the bottom
    // of check_ring_signature; an 8-torsion component here can in principle be
    // steered to cancel in the encoded identity while the prime-order ring closure
    // fails. Hard-reject torsion to keep the soundness proof's prime-order
    // assumption intact. check_subgroup() implies curve membership, so it subsumes
    // .valid().
    if (!A.check_subgroup() || !B.check_subgroup() || !C.check_subgroup() || !D.check_subgroup())
    {
        return false;
    }

    if (X.size() != m || Y.size() != m || f.size() != m)
    {
        return false;
    }

    // X[j] enters the RX MSM as -x^j * X[j]; torsion on these polynomial proof
    // points has the same identity-cancellation threat as A/B/C/D above.
    // Subgroup-check, not just curve-check.
    for (const auto &point : X)
    {
        if (!point.check_subgroup())
        {
            return false;
        }
    }

    // Y[j] enters the RY MSM as -x^j * Y[j] -- same rationale as X above.
    for (const auto &point : Y)
    {
        if (!point.check_subgroup())
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

void triptych_signature_t::deserialize(const std::vector<unsigned char> &data)
{
    Serialization::deserializer_t reader(data);

    deserialize(reader);
}

void triptych_signature_t::deserialize(Serialization::deserializer_t &reader)
{
    try
    {
        A = reader.pod<point_t>();

        B = reader.pod<point_t>();

        C = reader.pod<point_t>();

        D = reader.pod<point_t>();

        X = reader.podV<point_t>();

        Y = reader.podV<point_t>();

        f = reader.podVV<scalar_t>();

        zA = reader.pod<scalar_t>();

        zC = reader.pod<scalar_t>();

        z = reader.pod<scalar_t>();

        commitment_image = reader.pod<key_image_t>();

        pseudo_commitment = reader.pod<pedersen_commitment_t>();
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize triptych_signature_t");
}

void triptych_signature_t::fromJSON(const JSONValue &j)
{
    try
    {
        JSON_OBJECT_OR_THROW()

        LOAD_KEY_FROM_JSON(A);

        LOAD_KEY_FROM_JSON(B);

        LOAD_KEY_FROM_JSON(C);

        LOAD_KEY_FROM_JSON(D);

        LOAD_KEYV_FROM_JSON(X, point_t);

        LOAD_KEYV_FROM_JSON(Y, point_t);

        LOAD_KEYVV_FROM_JSON(f, scalar_t);

        LOAD_KEY_FROM_JSON(zA);

        LOAD_KEY_FROM_JSON(zC);

        LOAD_KEY_FROM_JSON(z);

        LOAD_KEY_FROM_JSON(commitment_image);

        LOAD_KEY_FROM_JSON(pseudo_commitment);
    }
    SMART_CATCH(std::invalid_argument, "Could not deserialize triptych_signature_t");
}

void triptych_signature_t::fromJSON(const JSONValue &val, const std::string &key)
{
    if (!has_member(val, std::string(key)))
    {
        throw std::invalid_argument(std::string(key) + " not found in JSON object");
    }

    const auto &j = get_json_value(val, key);

    fromJSON(j);
}

hash_t triptych_signature_t::hash() const
{
    const auto serialized = serialize();

    return hash_t::sha3(serialized);
}

void triptych_signature_t::serialize(Serialization::serializer_t &writer) const
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

std::vector<unsigned char> triptych_signature_t::serialize() const
{
    Serialization::serializer_t writer;

    serialize(writer);

    return writer.vector();
}

size_t triptych_signature_t::size() const
{
    return serialize().size();
}

void triptych_signature_t::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
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

std::string triptych_signature_t::to_string() const
{
    const auto bytes = serialize();

    return Serialization::to_hex(bytes.data(), bytes.size());
}
