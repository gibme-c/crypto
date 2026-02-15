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
 * @file crypto_triptych_signature_t.h
 * @brief Triptych logarithmic-size ring signature data structure.
 */

#ifndef CRYPTO_TRIPTYCH_T
#define CRYPTO_TRIPTYCH_T

#include <types/crypto_hash_t.h>
#include <types/crypto_point_t.h>
#include <types/crypto_scalar_t.h>

/**
 * @brief A Triptych ring signature with logarithmic proof size.
 *
 * Triptych is a next-generation ring signature scheme where the proof size grows as O(log n)
 * in the number of ring members, rather than O(n) like CLSAG. This makes it practical to use
 * much larger anonymity sets -- a ring of 1024 members produces a signature only modestly
 * larger than one for 64 members.
 *
 * Like CLSAG, Triptych is linkable (it produces a key image to detect double-spending) and
 * supports Pedersen commitments for confidential amounts. The signature additionally supports
 * a split signing flow via prepare/complete for use cases where the secret key is split across
 * multiple parties or devices.
 *
 * The proof is structured around a matrix decomposition of the signer's index in base n with
 * m digits. The ring size is n^m, and the proof contains O(m) group elements and scalars.
 * Typical parameters are n=2 (binary decomposition), giving log2(ring_size) proof components.
 *
 * The proof elements A, B, C, D are commitment points, X and Y are per-digit auxiliary points,
 * f is the m-by-(n-1) matrix of response scalars, and zA, zC, z are the final response scalars.
 */
struct crypto_triptych_signature_t final : Serializable
{
    crypto_triptych_signature_t() = default;

    crypto_triptych_signature_t(std::initializer_list<unsigned char> input);

    explicit crypto_triptych_signature_t(const std::vector<unsigned char> &input);

    explicit crypto_triptych_signature_t(const std::string &input);

    JSON_OBJECT_CONSTRUCTOR(crypto_triptych_signature_t, fromJSON)

    crypto_triptych_signature_t(
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
        const crypto_scalar_t &z);

    explicit crypto_triptych_signature_t(Serialization::deserializer_t &reader);

    /**
     * Checks that the basic construction of the signature is valid.
     *
     * Validates that all proof components have the expected dimensions for the given
     * decomposition parameters. This is a structural check only -- it does not verify
     * cryptographic correctness.
     *
     * @param m the number of digits in the base-n decomposition of the ring index
     * @param n the base of the decomposition (default 2 for binary)
     * @return true if all component dimensions are consistent with the (m, n) parameters
     */
    [[nodiscard]] bool check_construction(size_t m, size_t n = 2) const;

    void deserialize(const std::vector<unsigned char> &data) override;

    /**
     * Deserializes the struct from a byte array
     * @param reader
     */
    void deserialize(Serialization::deserializer_t &reader) override;

    /**
     * Deserializes the struct from JSON
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
    JSON_TO_FUNC(toJSON) override;

    /**
     * Returns the hex encoded serialized byte array
     * @return hex string of the serialized signature
     */
    [[nodiscard]] std::string to_string() const override;

    /** @brief Key image for the commitment blinding factor, enabling linkability on commitments. */
    crypto_key_image_t commitment_image;

    /** @brief Pseudo output commitment -- a re-blinded commitment to the same value, used for balance proofs. */
    crypto_pedersen_commitment_t pseudo_commitment;

    /** @brief Proof commitment points. A and B commit to the signer's index decomposition,
     *  C commits to the blinding factor difference, and D is an auxiliary commitment for linkability. */
    crypto_point_t A, B, C, D;

    /** @brief Per-digit auxiliary points (m elements each). X and Y encode the one-of-many proof
     *  structure across each digit position of the decomposed index. */
    std::vector<crypto_point_t> X, Y;

    /** @brief Response scalar matrix (m rows, each with n-1 scalars). Encodes the sigma-protocol
     *  responses for the one-of-n proof at each digit position. */
    std::vector<std::vector<crypto_scalar_t>> f;

    /** @brief Final response scalars. zA responds for the A commitment, zC for the C commitment,
     *  and z ties together the overall proof. */
    crypto_scalar_t zA, zC, z;
};

namespace std
{
    inline ostream &operator<<(ostream &os, const crypto_triptych_signature_t &value)
    {
        os << "Triptych [" << value.size() << " bytes]: " << value.hash() << std::endl
           << "\t" << PAD_NAMED(value.A, "A", 17) << std::endl
           << "\t" << PAD_NAMED(value.B, "B", 17) << std::endl
           << "\t" << PAD_NAMED(value.C, "C", 17) << std::endl
           << "\t" << PAD_NAMED(value.D, "D", 17) << std::endl
           << "\t" << PAD_STR("X", 17) << ":" << std::endl;

        for (const auto &val : value.X)
        {
            os << PAD_STR("\t", 20) << val << std::endl;
        }
        os << std::endl;

        os << "\t" << PAD_STR("Y", 17) << ":" << std::endl;

        for (const auto &val : value.Y)
        {
            os << PAD_STR("\t", 20) << val << std::endl;
        }
        os << std::endl;

        os << "\t" << PAD_STR("f", 17) << ":" << std::endl;
        for (const auto &level1 : value.f)
        {
            for (const auto &val : level1)
            {
                os << PAD_STR("\t", 20) << val << std::endl;
            }

            os << std::endl;
        }
        os << std::endl;

        os << "\t" << PAD_NAMED(value.zA, "zA", 17) << std::endl
           << "\t" << PAD_NAMED(value.zC, "zC", 17) << std::endl
           << "\t" << PAD_NAMED(value.z, "z", 17) << std::endl
           << "\t" << PAD_NAMED(value.commitment_image, "commitment_image", 17) << std::endl
           << "\t" << PAD_NAMED(value.pseudo_commitment, "pseudo_commitment", 17) << std::endl;

        return os;
    }
} // namespace std

#endif
