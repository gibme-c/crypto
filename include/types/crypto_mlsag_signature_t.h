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
 * @file crypto_mlsag_signature_t.h
 * @brief MLSAG (Multilayered Linkable Spontaneous Anonymous Group) ring signature data structure.
 */

#ifndef CRYPTO_MLSAG_T
#define CRYPTO_MLSAG_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * @brief An MLSAG (Multilayered Linkable Spontaneous Anonymous Group) ring signature.
 *
 * MLSAG is a ring signature scheme that proves you own one of N public keys in a set (the "ring")
 * without revealing which key is yours. It is "linkable" because it produces a key image -- a
 * deterministic tag derived from your secret key -- that lets anyone detect if the same key signs
 * twice, preventing double-spending in privacy-preserving transactions.
 *
 * MLSAG uses per-column response scalars: one scalar per ring member for the key column (M=1),
 * and optionally a second scalar per ring member for the commitment column (M=2). This results
 * in roughly twice the signature size of CLSAG when commitments are used.
 *
 * When used with Pedersen commitments (for confidential amounts), the signature also includes a
 * commitment_image and pseudo_commitment that prove the signer's commitment belongs to the ring
 * of commitments without revealing which one, while preserving balance.
 */
struct crypto_mlsag_signature_t final : Serializable
{
    crypto_mlsag_signature_t() = default;

    crypto_mlsag_signature_t(std::initializer_list<unsigned char> input);

    explicit crypto_mlsag_signature_t(const std::vector<unsigned char> &input);

    explicit crypto_mlsag_signature_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_mlsag_signature_t, fromJSON);

    crypto_mlsag_signature_t(
        std::vector<crypto_scalar_t> key_scalars,
        std::vector<crypto_scalar_t> commitment_scalars,
        const crypto_scalar_t &challenge,
        const crypto_key_image_t &commitment_image = Crypto::Z,
        const crypto_pedersen_commitment_t &pseudo_commitment = Crypto::Z);

    explicit crypto_mlsag_signature_t(Serialization::deserializer_t &reader);

    /**
     * Checks that the basic construction of the signature is valid.
     *
     * Validates structural properties: correct number of response scalars for the ring size,
     * non-zero challenge, and (if commitments are used) valid commitment_image and pseudo_commitment.
     * This is a structural check only -- it does not verify cryptographic correctness.
     *
     * @param ring_size the number of public keys in the ring
     * @param use_commitments whether this signature includes Pedersen commitment components
     * @return true if the signature has a structurally valid construction
     */
    [[nodiscard]] bool check_construction(size_t ring_size, bool use_commitments = false) const;

    /**
     * Deserializes the struct from a byte array
     * @param data
     */
    void deserialize(const std::vector<unsigned char> &data) override;

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(Serialization::deserializer_t &reader) override;

    /**
     * Loads the structure from a JSON object
     * @param j
     */
    JSON_FROM_FUNC(fromJSON) override;

    /**
     * Deserializes the struct from a JSON property
     * @param val
     * @param key
     */
    JSON_FROM_KEY_FUNC(fromJSON) override;

    /**
     * Provides the hash of the serialized structure
     * @return the SHA3-256 hash of the serialized byte representation
     */
    [[nodiscard]] crypto_hash_t hash() const;

    /**
     * Serializes the struct to a byte array
     * @param writer the serializer to write into
     */
    void serialize(Serialization::serializer_t &writer) const override;

    /**
     * Serializes the struct to a byte array
     * @return the serialized byte vector
     */
    [[nodiscard]] std::vector<unsigned char> serialize() const override;

    /**
     * Returns the serialized byte size
     * @return size in bytes
     */
    [[nodiscard]] size_t size() const override;

    /**
     * Writes the structure as JSON to the provided writer
     * @param writer the JSON writer to output into
     */
    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const override;

    /**
     * Returns the hex encoded serialized byte array
     * @return hex string of the serialized signature
     */
    [[nodiscard]] std::string to_string() const override;

    /** @brief Response scalars for the key column, one per ring member. */
    std::vector<crypto_scalar_t> key_scalars;

    /** @brief Response scalars for the commitment column, one per ring member.
     *  Empty when commitments are not used. */
    std::vector<crypto_scalar_t> commitment_scalars;

    /** @brief Key image for the commitment component (only meaningful when using commitments).
     *  Derived deterministically from the signer's commitment blinding factor, enabling linkability
     *  on the commitment side. Set to the identity point when commitments are not used. */
    crypto_key_image_t commitment_image;

    /** @brief The initial challenge scalar (h0) that seeds the ring verification loop.
     *  The verifier recomputes the challenge chain from h0 and checks that it closes. */
    crypto_scalar_t challenge;

    /** @brief Pseudo output commitment (only meaningful when using commitments).
     *  A re-blinded Pedersen commitment to the same amount as the real commitment, used to
     *  prove balance across inputs and outputs without revealing values. Set to the identity
     *  point when commitments are not used. */
    crypto_pedersen_commitment_t pseudo_commitment;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_mlsag_signature_t &value)
    {
        os << "MLSAG [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_STR("key_scalars", 17) << ":" << std::endl;

        for (const auto &val : value.key_scalars)
        {
            os << PAD_STR("\t", 20) << val << std::endl;
        }

        if (!value.commitment_scalars.empty())
        {
            os << "\t" << PAD_STR("commit_scalars", 17) << ":" << std::endl;

            for (const auto &val : value.commitment_scalars)
            {
                os << PAD_STR("\t", 20) << val << std::endl;
            }
        }

        os << "\t" << PAD_NAMED(value.challenge, "challenge", 17) << std::endl;

        if (value.commitment_image.valid())
        {
            os << "\t" << PAD_NAMED(value.commitment_image, "commitment_image", 17) << std::endl
               << "\t" << PAD_NAMED(value.pseudo_commitment, "pseudo_commitment", 17) << std::endl;
        }

        return os;
    }
} // namespace std

#endif
