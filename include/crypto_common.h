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

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <crypto_config.h>
#include <types/crypto_scalar_vector_t.h>

namespace Crypto
{
    namespace AES
    {
        /**
         * Decrypts data from the provided hexadecimal encoded encrypted string using the supplied password
         *
         * @param input
         * @param password
         * @param iterations
         * @return
         */
        std::string decrypt(
            const std::string &input,
            const std::string &password,
            size_t iterations = CRYPTO_PBKDF2_ITERATIONS);

        /**
         * Encrypts the provided string using the supplied password into a hexadecimal encoded encrypted string
         *
         * @param input
         * @param password
         * @param iterations
         * @return
         */
        std::string encrypt(
            const std::string &input,
            const std::string &password,
            size_t iterations = CRYPTO_PBKDF2_ITERATIONS);
    } // namespace AES

    /**
     * Calculates the exponent of 2^e that matches the target value
     * @param target_value
     * @return
     */
    std::tuple<bool, size_t> calculate_base2_exponent(const size_t &target_value);

    /**
     * Checks to validate that the given value is a point on the curve
     * @param value
     * @return
     */
    template<typename T> bool check_point(const T &value)
    {
        return crypto_point_t::check(value);
    }

    /**
     * Checks to validate that the given value is a reduced scalar
     * @param value
     * @return
     */
    template<typename T> bool check_scalar(const T &value)
    {
        return crypto_scalar_t::check(value);
    }

    /**
     * Checks for point torsion
     * @param value
     * @return
     */
    bool check_torsion(const crypto_point_t &value);

    /**
     * Generates a commitment tensor point
     * @param point
     * @param i
     * @param j
     * @param k
     * @return
     */
    crypto_point_t commitment_tensor_point(const crypto_point_t &point, size_t i, size_t j, size_t k = 0);

    /**
     * Calculates a convolution of a degree-one polynomial
     * @param x
     * @param y
     * @return
     */
    std::vector<crypto_scalar_t> convolve(const crypto_scalar_vector_t &x, const std::vector<crypto_scalar_t> &y);

    /**
     * Generates the derivation scalar
     * Ds = H(D || output_index) mod l
     * @param derivation
     * @param output_index
     * @return
     */
    crypto_scalar_t derivation_to_scalar(const crypto_derivation_t &derivation, uint64_t output_index = 0);

    /**
     * Calculates the public ephemeral given the derivation and the destination public key
     * P = [(Ds * G) + B] mod l
     * @param derivation_scalar
     * @param public_key
     * @return
     */
    crypto_public_key_t
        derive_public_key(const crypto_scalar_t &derivation_scalar, const crypto_public_key_t &public_key);

    /**
     * Calculates the secret ephemeral given the derivation and the destination secret key
     * p = (Ds + b) mod l
     * @param derivation_scalar
     * @param secret_key
     * @return
     */
    crypto_scalar_t derive_secret_key(const crypto_scalar_t &derivation_scalar, const crypto_scalar_t &secret_key);

    /**
     * Generates a key derivation
     * D = (a * B) mod l
     * @param public_key
     * @param secret_key
     * @return
     */
    crypto_derivation_t
        generate_key_derivation(const crypto_public_key_t &public_key, const crypto_scalar_t &secret_key);

    /**
     * Generates a key image such that
     * I = Hp(P) * x
     * @param public_ephemeral
     * @param secret_ephemeral
     * @return
     */
    crypto_key_image_t
        generate_key_image(const crypto_public_key_t &public_ephemeral, const crypto_scalar_t &secret_ephemeral);

    /**
     * Generates a key image such that
     * I = (1/x) * U
     * @param secret_ephemeral
     * @return
     */
    crypto_key_image_t generate_key_image_v2(const crypto_scalar_t &secret_ephemeral);

    /**
     * Generates a set of random keys
     * a = random_scalar()
     * A = (a * G) mod l
     *
     * NOTE: Keys generated by this method should NEVER be used for in wallet addresses.
     * Please refer to generate_wallet_spend_keys() and generate_wallet_view_keys()
     * for the deterministic methods to generate keys from a seed that allow for
     * recoverable keys.
     *
     */
    std::tuple<crypto_public_key_t, crypto_scalar_t> generate_keys();

    /**
     * Generates a set of random key pairs
     *
     * NOTE: Keys generated by this method should NEVER be used for in wallet addresses.
     * Please refer to generate_wallet_spend_keys() and generate_wallet_view_keys()
     * for the deterministic methods to generate keys from a seed that allow for
     * recoverable keys.
     *
     * @param count
     * @return
     */
    std::tuple<std::vector<crypto_public_key_t>, std::vector<crypto_scalar_t>> generate_keys_m(size_t count = 1);

    /**
     * Compute the Kronecker delta
     * @param a
     * @param b
     * @return
     */
    crypto_scalar_t kronecker_delta(const crypto_scalar_t &a, const crypto_scalar_t &b);

    /**
     * Compute the Kronecker delta
     * @param a
     * @param b
     * @return
     */
    crypto_scalar_t kronecker_delta(size_t a, size_t b);

    /**
     * Rounds the given value to the next power of 2
     * @param value
     * @return
     */
    size_t pow2_round(size_t value);

    /**
     * Much like derive_public_key() but determines the public_key used from the public ephemeral
     * B = P - [H(D || output_index) mod l]
     * @param derivation
     * @param output_index
     * @param public_ephemeral
     * @return
     */
    crypto_public_key_t underive_public_key(
        const crypto_derivation_t &derivation,
        uint64_t output_index,
        const crypto_public_key_t &public_ephemeral);
} // namespace Crypto

#endif // CRYPTO_COMMON_H
