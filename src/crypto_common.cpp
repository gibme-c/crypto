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

#include <crypto_common.h>
#include <crypto_constants.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha3.h>
#include <helpers/random_bytes.h>
#include <types/crypto_scalar_vector_t.h>

namespace Crypto
{
    namespace AES
    {
        std::string decrypt(const std::string &input, const std::string &password, size_t iterations)
        {
            // load the hexadecimal encoded string
            auto reader = Serialization::deserializer_t(input);

            CryptoPP::byte key[16] = {0}, salt[16] = {0};

            if (reader.size() < sizeof(salt))
            {
                throw std::invalid_argument("Ciphertext does not contain enough data to include the salt");
            }

            // pull out the salt
            {
                const auto bytes = reader.bytes(sizeof(salt));

                std::copy(bytes.begin(), bytes.end(), salt);
            }

            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;

            // derive the AES key from the password and salt
            pbkdf2.DeriveKey(
                key,
                sizeof(key),
                0,
                reinterpret_cast<const CryptoPP::byte *>(password.c_str()),
                password.size(),
                salt,
                sizeof(salt),
                iterations);

            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbc_decryption;

            cbc_decryption.SetKeyWithIV(key, sizeof(key), salt);

            std::string decrypted;

            const auto buffer = reader.unread_data();

            try
            {
                CryptoPP::StringSource(
                    reinterpret_cast<const CryptoPP::byte *>(buffer.data()),
                    buffer.size(),
                    true,
                    new CryptoPP::StreamTransformationFilter(cbc_decryption, new CryptoPP::StringSink(decrypted)));
            }
            catch (const CryptoPP::Exception &)
            {
                throw std::invalid_argument("Wrong password supplied for decryption");
            }

            return decrypted;
        }

        std::string encrypt(const std::string &input, const std::string &password, size_t iterations)
        {
            CryptoPP::byte key[16] = {0}, salt[16] = {0};

            // generate a random salt
            random_bytes(sizeof(salt), salt);

            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512> pbkdf2;

            // derive the AES key from the password and salt
            pbkdf2.DeriveKey(
                key,
                sizeof(key),
                0,
                reinterpret_cast<const CryptoPP::byte *>(password.c_str()),
                password.size(),
                salt,
                sizeof(salt),
                iterations);

            CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbc_encryption;

            cbc_encryption.SetKeyWithIV(key, sizeof(key), salt);

            std::vector<CryptoPP::byte> encrypted;

            CryptoPP::StringSource(
                input,
                true,
                new CryptoPP::StreamTransformationFilter(cbc_encryption, new CryptoPP::VectorSink(encrypted)));

            auto writer = Serialization::serializer_t();

            // pack the salt on to the front
            writer.bytes(salt, sizeof(salt));

            // append the encrypted data
            writer.bytes(encrypted.data(), encrypted.size());

            // return it as a hexadecimal encoded string
            return writer.to_string();
        }
    } // namespace AES

    std::tuple<bool, size_t> calculate_base2_exponent(const size_t &target_value)
    {
        const auto rounded = pow2_round(target_value);

        if (rounded != target_value)
        {
            return {false, 0};
        }

        for (size_t exponent = 0; exponent < 63; ++exponent)
        {
            const auto val = 1 << exponent;

            if (val == target_value)
            {
                return {true, exponent};
            }
        }

        return {false, 0};
    }

    bool check_torsion(const crypto_point_t &value)
    {
        if (Crypto::INV_EIGHT * (Crypto::EIGHT * value) != value || value.empty())
        {
            return false;
        }

        return true;
    }

    crypto_point_t commitment_tensor_point(const crypto_point_t &point, size_t i, size_t j, size_t k)
    {
        auto writer = Serialization::serializer_t();

        writer.pod(point);

        writer.uint64(i);

        writer.uint64(j);

        writer.uint64(k);

        return crypto_hash_t::sha3(writer).point();
    }

    std::vector<crypto_scalar_t> convolve(const crypto_scalar_vector_t &x, const std::vector<crypto_scalar_t> &y)
    {
        if (y.size() != 2)
        {
            throw std::runtime_error("requires a degree-one polynomial");
        }

        std::vector<crypto_scalar_t> result(x.size() + 1, Crypto::ZERO);

        for (size_t i = 0; i < x.size(); ++i)
        {
            for (size_t j = 0; j < y.size(); ++j)
            {
                result[i + j] += x[i] * y[j];
            }
        }

        return result;
    }

    crypto_scalar_t derivation_to_scalar(const crypto_derivation_t &derivation, const uint64_t output_index)
    {
        auto writer = Serialization::serializer_t();

        writer.pod(DERIVATION_DOMAIN_0);

        writer.pod(derivation);

        writer.uint64(output_index);

        return crypto_hash_t::sha3(writer).scalar();
    }

    crypto_public_key_t
        derive_public_key(const crypto_scalar_t &derivation_scalar, const crypto_public_key_t &public_key)
    {
        SCALAR_NZ_OR_THROW(derivation_scalar);

        // P = [A + (Ds * G)] mod l
        return (derivation_scalar * Crypto::G) + public_key;
    }

    crypto_scalar_t derive_secret_key(const crypto_scalar_t &derivation_scalar, const crypto_scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(derivation_scalar);

        SCALAR_NZ_OR_THROW(secret_key);

        // p = (Ds + a) mod l
        return derivation_scalar + secret_key;
    }

    crypto_derivation_t
        generate_key_derivation(const crypto_public_key_t &public_key, const crypto_scalar_t &secret_key)
    {
        SCALAR_NZ_OR_THROW(secret_key);

        // D = (a * B) mod l
        return (secret_key * public_key).mul8();
    }

    crypto_key_image_t
        generate_key_image(const crypto_public_key_t &public_ephemeral, const crypto_scalar_t &secret_ephemeral)
    {
        SCALAR_NZ_OR_THROW(secret_ephemeral);

        // I = [Hp(P) * x] mod l
        return secret_ephemeral * crypto_hash_t::sha3(public_ephemeral).point();
    }

    crypto_key_image_t generate_key_image_v2(const crypto_scalar_t &secret_ephemeral)
    {
        SCALAR_NZ_OR_THROW(secret_ephemeral);

        // I = 1/x * U
        return secret_ephemeral.invert() * Crypto::U;
    }

    std::tuple<crypto_public_key_t, crypto_scalar_t> generate_keys()
    {
        crypto_scalar_t secret_key = crypto_scalar_t::random();

        // A = (a * G) mod l
        return {secret_key * Crypto::G, secret_key};
    }

    std::tuple<std::vector<crypto_public_key_t>, std::vector<crypto_scalar_t>> generate_keys_m(size_t count)
    {
        std::vector<crypto_public_key_t> public_keys;

        std::vector<crypto_scalar_t> secret_keys;

        for (size_t i = 0; i < count; ++i)
        {
            const auto [public_key, secret_key] = generate_keys();

            public_keys.push_back(public_key);

            secret_keys.push_back(secret_key);
        }

        return {public_keys, secret_keys};
    }

    crypto_scalar_t kronecker_delta(const crypto_scalar_t &a, const crypto_scalar_t &b)
    {
        if (a == b)
        {
            return Crypto::ONE;
        }

        return Crypto::ZERO;
    }

    crypto_scalar_t kronecker_delta(size_t a, size_t b)
    {
        return kronecker_delta(crypto_scalar_t(a), crypto_scalar_t(b));
    }

    size_t pow2_round(size_t value)
    {
        size_t count = 0;

        if (value && !(value & (value - 1)))
        {
            return value;
        }

        while (value != 0)
        {
            value >>= uint64_t(1);

            count++;
        }

        return uint64_t(1) << count;
    }

    crypto_public_key_t underive_public_key(
        const crypto_derivation_t &derivation,
        uint64_t output_index,
        const crypto_public_key_t &public_ephemeral)
    {
        const auto scalar = derivation_to_scalar(derivation, output_index);

        // A = [P - (Ds * G)] mod l
        return public_ephemeral - (scalar * Crypto::G);
    }
} // namespace Crypto
