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
 * @file crypto_common.cpp
 * @brief Core Crypto:: namespace: AES encrypt/decrypt, key derivation, key images, stealth addresses, utilities.
 */

#include <core/crypto_common.h>
#include <core/crypto_constants.h>
#include <ed25519.h>
#include <ed25519/include/ed25519_secure_erase.h>
#include <helpers/constant_time.h>
#include <randompp.hpp>
#include <ranshaw.h>
#include <tinyaes/cbc.h>
#include <tinysha.h>
#include <types/scalar_vector_t.h>

namespace Crypto
{
    void init()
    {
        ed25519_init(false);

        ranshaw::init();
    }

    void autotune()
    {
        ed25519_init(true);

        ranshaw::autotune();
    }

    // ---- AES-128-CBC with PBKDF2-SHA3-512 key derivation and HMAC-SHA3-256 authentication ----
    // Key split: 16 bytes AES key + 16 bytes HMAC key + 16 bytes IV from 48-byte PBKDF2 output.
    // The IV is derived independently from the salt to avoid reusing the salt as both
    // PBKDF2 input and CBC initialization vector.
    namespace AES
    {
        std::string decrypt(const std::string &input, const std::string &password, size_t iterations)
        {
            static constexpr size_t HMAC_SIZE = 32;

            if (iterations > UINT32_MAX)
            {
                throw std::invalid_argument("iterations exceeds uint32_t maximum");
            }

            // load the hexadecimal encoded string
            auto reader = Serialization::deserializer_t(input);

            unsigned char derived_key[48] = {0}, salt[16] = {0};

            if (reader.size() < sizeof(salt) + HMAC_SIZE)
            {
                throw std::invalid_argument("Ciphertext does not contain enough data");
            }

            // pull out the salt
            {
                const auto bytes = reader.bytes(sizeof(salt));

                std::copy(bytes.begin(), bytes.end(), salt);
            }

            // derive 48 bytes: 16 AES key + 16 HMAC key + 16 IV
            tinysha_pbkdf2_sha3_512(
                reinterpret_cast<const uint8_t *>(password.c_str()),
                password.size(),
                salt,
                sizeof(salt),
                static_cast<uint32_t>(iterations),
                derived_key,
                sizeof(derived_key));

            const unsigned char *aes_key = derived_key;
            const unsigned char *hmac_key = derived_key + 16;
            const unsigned char *iv = derived_key + 32;

            const auto remaining = reader.unread_data();

            if (remaining.size() < HMAC_SIZE)
            {
                // SECURITY: erase derived key material before throwing
                ed25519_secure_erase(derived_key, sizeof(derived_key));

                throw std::invalid_argument("Ciphertext does not contain enough data");
            }

            // separate ciphertext and stored HMAC
            const auto ciphertext_size = remaining.size() - HMAC_SIZE;
            const auto *ciphertext_data = remaining.data();
            const auto *stored_hmac = remaining.data() + ciphertext_size;

            // recompute HMAC over salt || ciphertext
            unsigned char computed_hmac[HMAC_SIZE] = {0};
            {
                std::vector<uint8_t> hmac_data;
                hmac_data.reserve(sizeof(salt) + ciphertext_size);
                hmac_data.insert(hmac_data.end(), salt, salt + sizeof(salt));
                hmac_data.insert(hmac_data.end(), ciphertext_data, ciphertext_data + ciphertext_size);

                tinysha_hmac_sha3_256(hmac_key, 16, hmac_data.data(), hmac_data.size(), computed_hmac, HMAC_SIZE);
            }

            // constant-time comparison (evaluate before branching)
            const bool hmac_ok = constant_time_equals(computed_hmac, stored_hmac, HMAC_SIZE);

            // always attempt decryption to avoid timing differences
            std::vector<uint8_t> plaintext_buf(ciphertext_size);
            size_t plaintext_len = plaintext_buf.size();

            const auto rc = tinyaes_cbc_decrypt_pkcs7(
                aes_key, 16, iv, ciphertext_data, ciphertext_size, plaintext_buf.data(), &plaintext_len);

            // SECURITY: erase derived key material before any throw or return
            ed25519_secure_erase(derived_key, sizeof(derived_key));

            if (!hmac_ok || rc != TINYAES_OK)
            {
                throw std::invalid_argument("Decryption failed");
            }

            return std::string(reinterpret_cast<const char *>(plaintext_buf.data()), plaintext_len);
        }

        std::string encrypt(const std::string &input, const std::string &password, size_t iterations)
        {
            static constexpr size_t HMAC_SIZE = 32;

            if (iterations > UINT32_MAX)
            {
                throw std::invalid_argument("iterations exceeds uint32_t maximum");
            }

            unsigned char derived_key[48] = {0}, salt[16] = {0};

            // generate a random salt
            randompp::random_bytes(sizeof(salt), salt);

            // derive 48 bytes: 16 AES key + 16 HMAC key + 16 IV
            tinysha_pbkdf2_sha3_512(
                reinterpret_cast<const uint8_t *>(password.c_str()),
                password.size(),
                salt,
                sizeof(salt),
                static_cast<uint32_t>(iterations),
                derived_key,
                sizeof(derived_key));

            const unsigned char *aes_key = derived_key;
            const unsigned char *hmac_key = derived_key + 16;
            const unsigned char *iv = derived_key + 32;

            std::vector<uint8_t> encrypted(input.size() + 16);
            size_t encrypted_len = encrypted.size();

            const auto rc = tinyaes_cbc_encrypt_pkcs7(
                aes_key,
                16,
                iv,
                reinterpret_cast<const uint8_t *>(input.data()),
                input.size(),
                encrypted.data(),
                &encrypted_len);

            if (rc != TINYAES_OK)
            {
                // SECURITY: erase derived key material before throwing
                ed25519_secure_erase(derived_key, sizeof(derived_key));

                throw std::runtime_error("AES encryption failed");
            }

            encrypted.resize(encrypted_len);

            // compute HMAC over salt || ciphertext
            unsigned char hmac_digest[HMAC_SIZE] = {0};
            {
                std::vector<uint8_t> hmac_data;
                hmac_data.reserve(sizeof(salt) + encrypted.size());
                hmac_data.insert(hmac_data.end(), salt, salt + sizeof(salt));
                hmac_data.insert(hmac_data.end(), encrypted.data(), encrypted.data() + encrypted.size());

                tinysha_hmac_sha3_256(hmac_key, 16, hmac_data.data(), hmac_data.size(), hmac_digest, HMAC_SIZE);
            }

            auto writer = Serialization::serializer_t();

            // pack the salt on to the front
            writer.bytes(salt, sizeof(salt));

            // append the encrypted data
            writer.bytes(encrypted.data(), encrypted.size());

            // append the HMAC
            writer.bytes(hmac_digest, HMAC_SIZE);

            // SECURITY: erase derived key material before return
            ed25519_secure_erase(derived_key, sizeof(derived_key));

            // return it as a hexadecimal encoded string
            return writer.to_string();
        }
    } // namespace AES

    scalar_t derivation_to_scalar(const derivation_t &derivation, const uint64_t output_index)
    {
        auto writer = Serialization::serializer_t();

        writer.pod(DERIVATION_DOMAIN_0);

        writer.pod(derivation);

        writer.uint64(output_index);

        return hash_t::sha3(writer).scalar();
    }

    public_key_t derive_public_key(const scalar_t &derivation_scalar, const public_key_t &public_key)
    {
        SCALAR_NZ_OR_THROW(derivation_scalar);

        {
            const bool valid_point = public_key.check();
            const bool valid_subgroup = public_key.check_subgroup();

            if (!(valid_point & valid_subgroup))
            {
                throw std::invalid_argument("public_key is not a valid point in the subgroup");
            }
        }

        // P = [A + (Ds * G)] mod l
        return (derivation_scalar * Crypto::G) + public_key;
    }

    scalar_t derive_secret_key(const scalar_t &derivation_scalar, const scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(derivation_scalar);

        SCALAR_NZ_OR_THROW(secret_key);

        // p = (Ds + a) mod l
        return derivation_scalar + secret_key;
    }

    derivation_t generate_key_derivation(const public_key_t &public_key, const scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(secret_key);

        {
            const bool valid_point = public_key.check();
            const bool valid_subgroup = public_key.check_subgroup();

            if (!(valid_point & valid_subgroup))
            {
                throw std::invalid_argument("public_key is not a valid point in the subgroup");
            }
        }

        // D = (a * B) mod l
        return (secret_key * public_key).mul8();
    }

    key_image_t generate_key_image(const public_key_t &public_ephemeral, const scalar_t &secret_ephemeral)
    {
        SCALAR_NZ_OR_THROW(secret_ephemeral);

        {
            const bool valid_point = public_ephemeral.check();
            const bool valid_subgroup = public_ephemeral.check_subgroup();

            if (!(valid_point & valid_subgroup))
            {
                throw std::invalid_argument("public_ephemeral is not a valid point in the subgroup");
            }
        }

        // I = [Hp(P) * x] mod l
        return secret_ephemeral * hash_t::sha3(public_ephemeral).point();
    }

    key_image_t generate_key_image_v2(const scalar_t &secret_ephemeral)
    {
        SCALAR_NZ_OR_THROW(secret_ephemeral);

        // I = 1/x * U
        return secret_ephemeral.invert() * Crypto::U;
    }

    std::tuple<public_key_t, scalar_t> generate_keys()
    {
        scalar_t secret_key = scalar_t::random();

        // A = (a * G) mod l
        return {secret_key * Crypto::G, secret_key};
    }

    std::tuple<std::vector<public_key_t>, std::vector<scalar_t>> generate_keys_m(size_t count)
    {
        std::vector<public_key_t> public_keys;

        std::vector<scalar_t> secret_keys;

        for (size_t i = 0; i < count; ++i)
        {
            const auto [public_key, secret_key] = generate_keys();

            public_keys.push_back(public_key);

            secret_keys.push_back(secret_key);
        }

        return {public_keys, secret_keys};
    }

    public_key_t
        underive_public_key(const derivation_t &derivation, uint64_t output_index, const public_key_t &public_ephemeral)
    {
        const auto scalar = derivation_to_scalar(derivation, output_index);

        // A = [P - (Ds * G)] mod l
        return public_ephemeral - (scalar * Crypto::G);
    }
} // namespace Crypto
