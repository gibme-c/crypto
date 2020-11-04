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

#include <crypto_constants.h>
#include <encoding/base58.h>
#include <helpers/scalar_transcript_t.h>
#include <proofs/audit.h>
#include <serialization.h>
#include <signatures/ring_signature_clsag.h>

namespace Crypto::Audit
{
    std::tuple<bool, std::vector<crypto_key_image_t>>
        check_outputs_proof(const std::vector<crypto_public_key_t> &public_ephemerals, const std::string &proof)
    {
        // try to decode the information from the Base58 encoded string
        auto [success, reader] = Base58::decode_check(proof);

        if (!success)
        {
            return {false, {}};
        }

        // extract the key images
        const auto key_images = reader.podV<crypto_key_image_t>();

        // extract the signatures
        std::vector<crypto_clsag_signature_t> signatures;

        {
            const auto count = reader.varint<uint64_t>();

            for (size_t i = 0; i < count; ++i)
            {
                signatures.emplace_back(reader);
            }
        }

        // verify that we have the proper count of key images and signatures for the public ephemerals we provided
        if (public_ephemerals.size() != key_images.size() || key_images.size() != signatures.size())
        {
            return {false, {}};
        }

        auto tr = scalar_transcript_t(OUTPUT_PROOF_DOMAIN);

        // loop through the signatures to check them all
        for (size_t i = 0; i < signatures.size(); ++i)
        {
            // building the transcript in this way (for the message digest) guarantees proper ordering
            tr.update(public_ephemerals[i], key_images[i]);

            // check that the signature is valid, if not, we're done here
            if (!Crypto::RingSignature::CLSAG::check_ring_signature(
                    tr.challenge<crypto_hash_t>(), key_images[i], {public_ephemerals[i]}, signatures[i]))
            {
                return {false, {}};
            }
        }

        // if everything checked out okay, return successfully
        return {true, key_images};
    }

    std::tuple<bool, std::string> generate_outputs_proof(const std::vector<crypto_scalar_t> &secret_ephemerals)
    {
        std::vector<crypto_public_key_t> public_ephemerals;

        std::vector<crypto_key_image_t> key_images;

        std::vector<crypto_clsag_signature_t> signatures;

        auto tr = scalar_transcript_t(OUTPUT_PROOF_DOMAIN);

        // loop through the secret keys provided and generate the proofs
        for (const auto &secret_ephemeral : secret_ephemerals)
        {
            const auto public_ephemeral = secret_ephemeral.point();

            const auto key_image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

            key_images.push_back(key_image);

            // building the transcript in this way (for the message digest) guarantees proper ordering
            tr.update(public_ephemeral, key_image);

            // generate the signature using the key image generated
            const auto [success, signature] = Crypto::RingSignature::CLSAG::generate_ring_signature(
                tr.challenge<crypto_hash_t>(), secret_ephemeral, {public_ephemeral});

            // if signature generation failed, something went terribly wrong
            if (!success)
            {
                return {false, std::string()};
            }

            signatures.push_back(signature);
        }

        // package up the information
        auto writer = Serialization::serializer_t();

        writer.pod(key_images);

        writer.varint(signatures.size());

        for (const auto &sig : signatures)
        {
            sig.serialize(writer);
        }

        // spit back the result as a Base58 check encoded string
        return {true, Base58::encode_check(writer)};
    }
} // namespace Crypto::Audit
