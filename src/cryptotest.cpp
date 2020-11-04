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

#include <benchmark.h>
#include <crypto.h>

using namespace Serialization;

#define RING_SIZE 4

const crypto_hash_t INPUT_DATA = {0xcf, 0xc7, 0x65, 0xd9, 0x05, 0xc6, 0x5e, 0x2b, 0x61, 0x81, 0x6d,
                                  0xc1, 0xf0, 0xfd, 0x69, 0xf6, 0xf6, 0x77, 0x9f, 0x36, 0xed, 0x62,
                                  0x39, 0xac, 0x7e, 0x21, 0xff, 0x51, 0xef, 0x2c, 0x89, 0x1e};

const crypto_hash_t SHA3_HASH = {0x97, 0x45, 0x06, 0x60, 0x1a, 0x60, 0xdc, 0x46, 0x5e, 0x6e, 0x9a,
                                 0xcd, 0xdb, 0x56, 0x38, 0x89, 0xe6, 0x34, 0x71, 0x84, 0x9e, 0xc4,
                                 0x19, 0x86, 0x56, 0x55, 0x03, 0x54, 0xb8, 0x54, 0x1f, 0xcb};

const auto SHA3_SLOW_0 = crypto_hash_t("974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb");

const auto SHA3_SLOW_4096 = crypto_hash_t("c031be420e429992443c33c2a453287e2678e70b8bce95dfe7357bcbf36ca86c");

const auto BLAKE2B = crypto_hash_t("56a8ef7f9d7db21fa29b83eb77551f0c3e312525d6151946261911fc38a508c4");

const auto ARGON2D_4_1024_1 = crypto_hash_t("cd65323e3e56272fd19b745b0673318b21c2be5257f918267998b341719c3d5a");

const auto ARGON2I_4_1024_1 = crypto_hash_t("debb2a3b51732bff26670753c5dbaedf6139c177108fe8e0744305c8d410a75a");

const auto ARGON2ID_4_1024_1 = crypto_hash_t("a6ac954bce48a46bc01a9b16b484ffb745401ae421b1b6f2e22cf474d4cac1c9");

const uint64_t BASE58_PREFIX = 0x106a1c;

template<typename T> static inline bool test_binary_encoding(const T &value)
{
    serializer_t writer;

    value.serialize(writer);

    deserializer_t reader(writer);

    T post_value;

    post_value.deserialize(reader);

    return value.hash() == post_value.hash();
}

template<typename T> static inline bool test_binary_encoding_v2(const T &value)
{
    Serialization::serializer_t writer;

    value.serialize(writer);

    Serialization::deserializer_t reader(writer);

    T post_value;

    post_value.deserialize(reader);

    return value.hash() == post_value.hash();
}

template<typename T> static inline bool test_binary_encoding_v3(const T &value)
{
    Serialization::serializer_t writer;

    value.serialize(writer);

    Serialization::deserializer_t reader(writer);

    T post_value;

    post_value.deserialize(reader);

    return value == post_value;
}

template<typename T> static inline bool test_json_encoding(const T &value)
{
    JSON_INIT_BUFFER(buffer, writer);

    value.toJSON(writer);

    JSON_DUMP_BUFFER(buffer, encoded);

    STR_TO_JSON(encoded, json_document);

    T post_value(json_document);

    return value.hash() == post_value.hash();
}

template<typename T> static inline bool test_json_encoding_v3(const T &value)
{
    JSON_INIT_BUFFER(buffer, writer);

    value.toJSON(writer);

    JSON_DUMP_BUFFER(buffer, encoded);

    STR_TO_JSON(encoded, json_document);

    T post_value(json_document);

    return value == post_value;
}

int main()
{
    std::cout << std::endl << std::endl << "Cryptographic Primitive Unit Tests" << std::endl << std::endl;

    std::cout << "Sanity Check" << std::endl << std::endl;

    {
        const auto point = crypto_point_t();

        std::cout << "crypto_point_t: ";

        if (!point.empty())
        {
            std::cout << "Failed" << std::endl;

            return 1;
        }

        std::cout << "Passed" << std::endl;

        const auto scalar = crypto_scalar_t();

        std::cout << "crypto_scalar_t: ";

        if (!scalar.empty())
        {
            std::cout << "Failed" << std::endl;

            return 1;
        }

        std::cout << "Passed" << std::endl;

        const auto signature = crypto_signature_t();

        std::cout << "crypto_signature_t: ";

        if (!signature.empty())
        {
            std::cout << "Failed" << std::endl;

            return 1;
        }

        std::cout << "Passed" << std::endl;

        const auto hash = crypto_hash_t();

        std::cout << "crypto_hash_t: ";

        if (!hash.empty())
        {
            std::cout << "Failed" << std::endl;

            return 1;
        }

        std::cout << "Passed" << std::endl;

        const auto entropy = crypto_entropy_t();

        std::cout << "crypto_entropy_t: ";

        if (!entropy.empty())
        {
            std::cout << "Failed" << std::endl;

            return 1;
        }

        std::cout << "Passed" << std::endl;
    }

    std::cout << std::endl << "Hashing" << std::endl << std::endl;

    std::cout << "Random Hash: " << crypto_hash_t::random() << std::endl << std::endl;

    std::cout << "Input Data: " << INPUT_DATA << std::endl << std::endl;

    // SHA-3 test
    {
        const auto hash = crypto_hash_t::sha3(INPUT_DATA);

        if (hash != SHA3_HASH)
        {
            std::cout << "Hashing::sha3: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Hashing::sha3: Passed!" << std::endl << std::endl;
    }

    // Blake2b Test
    {
        const auto hash = crypto_hash_t::blake2b(INPUT_DATA);

        if (hash != BLAKE2B)
        {
            std::cout << "Hashing::Blake2b: Failed! " << std::endl;
            std::cout << "Expected: " << BLAKE2B << std::endl;
            std::cout << "Received: " << hash << std::endl;

            return 1;
        }

        std::cout << "Hashing::Blake2b: Passed!" << std::endl << std::endl;
    }

    // Argon2d Test
    {
        const auto hash = crypto_hash_t::argon2d(INPUT_DATA, 4, 1024, 1);

        if (hash != ARGON2D_4_1024_1)
        {
            std::cout << "Hashing::Argon2d: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Hashing::Argon2d: Passed!" << std::endl << std::endl;
    }

    // Argon2i Test
    {
        const auto hash = crypto_hash_t::argon2i(INPUT_DATA, 4, 1024, 1);

        if (hash != ARGON2I_4_1024_1)
        {
            std::cout << "Hashing::Argon2i: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Hashing::Argon2i: Passed!" << std::endl << std::endl;
    }

    // Argon2id Test
    {
        const auto hash = crypto_hash_t::argon2id(INPUT_DATA, 4, 1024, 1);

        if (hash != ARGON2ID_4_1024_1)
        {
            std::cout << "Hashing::Argon2id: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Hashing::Argon2id: Passed!" << std::endl << std::endl;
    }

    // SHA-3 slow hash
    {
        auto hash = crypto_hash_t::sha3_slow(INPUT_DATA);

        if (hash != SHA3_SLOW_0)
        {
            std::cout << "Hashing::sha3_slow_hash: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Hashing::sha3_slow_hash: Passed!" << std::endl << std::endl;

        hash = crypto_hash_t::sha3_slow(INPUT_DATA, 4096);

        if (hash != SHA3_SLOW_4096)
        {
            std::cout << "Hashing::sha3_slow_hash[4096]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Hashing::sha3_slow_hash[4096]: Passed!" << std::endl << std::endl;
    }

    // AES Test
    {
        std::cout << "AES Test:" << std::endl;

        const auto input = std::string("cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e");

        std::cout << "\tInput:\t\t" << input << std::endl;

        const auto password = std::string("SuperSecretPassword");

        std::cout << "\tPassword:\t" << password << std::endl;

        const auto encrypted = Crypto::AES::encrypt(input, password);

        std::cout << "\tEncrypted:\t" << encrypted << std::endl;

        const auto decrypted = Crypto::AES::decrypt(encrypted, password);

        std::cout << "\tDecrypted:\t" << decrypted << std::endl;

        if (decrypted != input)
        {
            std::cout << "AES Test: Failed" << std::endl;

            return 1;
        }

        std::cout << "AES Test: Passed" << std::endl << std::endl;
    }

    // Base58 Test #1
    {
        std::cout << "Base58 Test #1:" << std::endl;

        const auto a = crypto_point_t::random();

        const auto b = crypto_point_t::random();

        serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::Base58::encode(writer.vector());

        std::cout << "\tRaw: " << writer.to_string() << std::endl << "\tEncoded: " << encoded << std::endl;

        auto [success, reader] = Crypto::Base58::decode(encoded);

        if (!success)
        {
            std::cout << "Crypto::Base58: Failed!" << std::endl;

            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<crypto_point_t>();

        const auto checkb = reader.pod<crypto_point_t>();

        if (checka != a || checkb != b || prefix != BASE58_PREFIX)
        {
            std::cout << "Crypto::Base58: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::Base58: Passed!" << std::endl << std::endl;
    }

    // Base58 Test #2
    {
        std::cout << "Base58 Test #2:" << std::endl;

        const auto a = crypto_point_t::random();

        const auto b = crypto_point_t::random();

        serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::Base58::encode_check(writer);

        std::cout << "\tRaw: " << writer.to_string() << std::endl << "\tEncoded: " << encoded << std::endl;

        auto [success, reader] = Crypto::Base58::decode_check(encoded);

        if (!success)
        {
            std::cout << "Crypto::Base58[check]: Failed!" << std::endl;

            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<crypto_point_t>();

        const auto checkb = reader.pod<crypto_point_t>();

        if (checka != a || checkb != b || prefix != BASE58_PREFIX)
        {
            std::cout << "Crypto::Base58[check]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::Base58[check]: Passed!" << std::endl << std::endl;
    }

    // CryptoNote Base58 Test #1
    {
        std::cout << "CryptoNote Base58 Test #1:" << std::endl;

        const auto a = crypto_point_t::random();

        const auto b = crypto_point_t::random();

        serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::CNBase58::encode_check(writer);

        std::cout << "\tRaw: " << writer.to_string() << std::endl << "\tEncoded: " << encoded << std::endl;

        auto [success, reader] = Crypto::CNBase58::decode(encoded);

        if (!success)
        {
            std::cout << "Crypto::CNBase58: Failed!" << std::endl;

            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<crypto_point_t>();

        const auto checkb = reader.pod<crypto_point_t>();

        if (checka != a || checkb != b || prefix != BASE58_PREFIX)
        {
            std::cout << "Crypto::CNBase58: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::CNBase58: Passed!" << std::endl << std::endl;
    }

    // CryptoNote Base58 Test #2
    {
        std::cout << "CryptoNote Base58 Test #2:" << std::endl;

        const auto a = crypto_point_t::random();

        const auto b = crypto_point_t::random();

        serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::CNBase58::encode_check(writer);

        std::cout << "\tRaw: " << writer.to_string() << std::endl << "\tEncoded: " << encoded << std::endl;

        auto [success, reader] = Crypto::CNBase58::decode_check(encoded);

        if (!success)
        {
            std::cout << "Crypto::CNBase58[check]: Failed!" << std::endl;

            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<crypto_point_t>();

        const auto checkb = reader.pod<crypto_point_t>();

        if (checka != a || checkb != b || prefix != BASE58_PREFIX)
        {
            std::cout << "Crypto::CNBase58[check]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::CNBase58[check]: Passed!" << std::endl << std::endl;
    }

    // 2^n rounding test
    {
        const auto val = Crypto::pow2_round(13);

        if (val != 16)
        {
            std::cout << "pow2_round: Failed!" << std::endl;

            return 1;
        }

        std::cout << "pow2_round: Passed!" << std::endl;
    }

    // check for randomness
    {
        const auto points = crypto_point_vector_t(crypto_point_t::random(20)).dedupe_sort();

        if (points.size() != 20)
        {
            std::cout << "Failed random points test! Very Bad!!!" << std::endl << std::endl << std::endl;
        }

        const auto scalars = crypto_scalar_vector_t(crypto_scalar_t::random(20)).dedupe_sort();

        if (scalars.size() != 20)
        {
            std::cout << "Failed random scalars test! Very Bad!!!" << std::endl << std::endl << std::endl;
        }
    }

    // check tests
    {
        const auto scalar = std::string("a03681f038b1aee4d417874fa551aaa8f4a608a70ddff0257dd93f932b8fef0e");

        const auto point = std::string("d555bf22bce71d4eff27aa7597b5590969e7eccdb67a52188d0d73d5ab82d414");

        if (!Crypto::check_scalar(scalar))
        {
            std::cout << "check_scalar: Failed! " << scalar << std::endl;

            return 1;
        }

        if (Crypto::check_scalar(point))
        {
            std::cout << "check_scalar: Failed! " << point << std::endl;

            return 1;
        }

        std::cout << "check_scalar: Passed!" << std::endl;

        if (!Crypto::check_point(point))
        {
            std::cout << "check_point: Failed! " << point << std::endl;

            return 1;
        }

        if (Crypto::check_point(scalar))
        {
            std::cout << "check_point: Failed! " << scalar << std::endl;

            return 1;
        }

        std::cout << "check_point: Passed!" << std::endl;
    }

    // Scalar bit vector test
    {
        const auto a = crypto_scalar_t::random();

        const auto bits = a.to_bits();

        crypto_scalar_t b(bits);

        if (b != a)
        {
            std::cout << "Scalar Bit Vector Test: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Scalar Bit Vector Test: Passed!" << std::endl << std::endl;
    }

    // Entropy Tests
    {
        const auto wallet_entropy = crypto_entropy_t::random(256, {});

        std::cout << "New Entropy:  " << wallet_entropy << std::endl;

        std::cout << "Mnemonic:  " << wallet_entropy.to_mnemonic_phrase() << std::endl;

        std::cout << "Timestamp: " << wallet_entropy.timestamp() << std::endl << std::endl;

        const auto wallet_entropy_2 = crypto_entropy_t::recover(wallet_entropy.to_mnemonic_phrase());

        std::cout << "New Entropy:  " << wallet_entropy_2 << std::endl;

        std::cout << "Mnemonic:  " << wallet_entropy_2.to_mnemonic_phrase() << std::endl;

        std::cout << "Timestamp: " << wallet_entropy_2.timestamp() << std::endl;

        if (wallet_entropy_2 != wallet_entropy)
        {
            std::cout << "Could not restore entropy" << std::endl;
        }

        std::cout << std::endl;
    }

    {
        const auto wallet_entropy = crypto_entropy_t::random(128, {}, false);

        std::cout << "New Entropy:  " << wallet_entropy << std::endl;

        std::cout << "Mnemonic:  " << wallet_entropy.to_mnemonic_phrase() << std::endl;

        std::cout << "Timestamp: " << wallet_entropy.timestamp() << std::endl << std::endl;

        const auto wallet_entropy_2 = crypto_entropy_t::recover(wallet_entropy.to_mnemonic_phrase());

        std::cout << "New Entropy:  " << wallet_entropy_2 << std::endl;

        std::cout << "Mnemonic:  " << wallet_entropy_2.to_mnemonic_phrase() << std::endl;

        std::cout << "Timestamp: " << wallet_entropy_2.timestamp() << std::endl;

        if (wallet_entropy_2 != wallet_entropy)
        {
            std::cout << "Could not restore entropy" << std::endl;
        }

        std::cout << std::endl;
    }

    const auto wallet_entropy = crypto_entropy_t::random();

    std::cout << std::endl << "Entropy: " << wallet_entropy << std::endl;

    const auto seed = crypto_seed_t(wallet_entropy);

    std::cout << "\tBIP-39 Seed: " << seed << std::endl;

    const auto [public_key, secret_key] = seed.generate_child_key(44, 0, 0, 0, 0).keys();

    std::cout << "\tSecret: " << secret_key << std::endl << "\tPublic: " << public_key << std::endl << std::endl;

    {
        const auto check = secret_key.point();

        if (check != public_key)
        {
            std::cout << "secret_key_to_public_key: Failed!" << std::endl;

            return 1;
        }

        std::cout << "secret_key_to_public_key: " << secret_key << std::endl
                  << "\t -> " << public_key << std::endl
                  << std::endl;
    }

    if (!test_binary_encoding_v3(wallet_entropy))
    {
        std::cout << "crypto_entropy_t binary encoding test failed!" << std::endl;

        return 1;
    }
    else
    {
        std::cout << "crypto_entropy_t binary encoding test passed!" << std::endl;
    }

    if (!test_json_encoding_v3(wallet_entropy))
    {
        std::cout << "crypto_entropy_t json encoding test failed!" << std::endl;

        return 1;
    }
    else
    {
        std::cout << "crypto_entropy_t json encoding test passed!" << std::endl;
    }

    if (!test_binary_encoding_v3(secret_key))
    {
        std::cout << "crypto_secret_key_t binary encoding test failed!" << std::endl;

        return 1;
    }
    else
    {
        std::cout << "crypto_secret_key_t binary encoding test passed!" << std::endl;
    }

    if (!test_json_encoding_v3(secret_key))
    {
        std::cout << "crypto_secret_key_t json encoding test failed!" << std::endl;

        return 1;
    }
    else
    {
        std::cout << "crypto_secret_key_t json encoding test passed!" << std::endl << std::endl;
    }

    // test subwallet-1
    {
        const auto [pub, subwallet] = seed.generate_child_key(44, 0, 0, 0, 1).keys();

        if (subwallet == secret_key)
        {
            std::cout << "generate_deterministic_subwallet_key(1): Failed!" << std::endl;
            std::cout << "Existing: " << secret_key << std::endl;
            std::cout << "Received: " << subwallet << std::endl;

            return 1;
        }

        std::cout << "generate_deterministic_subwallet_key(1): " << subwallet << std::endl;
    }

    // test subwallet-32
    {
        const auto [pub, subwallet] = seed.generate_child_key(44, 0, 0, 0, 32).keys();

        if (subwallet == secret_key)
        {
            std::cout << "generate_deterministic_subwallet_key(32): Failed!" << std::endl;
            std::cout << "Existing: " << secret_key << std::endl;
            std::cout << "Received: " << subwallet << std::endl;

            return 1;
        }

        std::cout << "generate_deterministic_subwallet_key(32): " << subwallet << std::endl;
    }

    const auto [pub2, secret_key2] = seed.generate_child_key(45, 0, 1, 0, 0).keys();

    if (secret_key2 == secret_key)
    {
        std::cout << "generate_view_keys: Failed!" << std::endl;
        std::cout << "Existing: " << secret_key << std::endl;
        std::cout << "Received: " << secret_key2 << std::endl;

        return 1;
    }

    std::cout << std::endl << "generate_view_keys: Passed!" << std::endl;

    const auto public_key2 = secret_key2.point();

    std::cout << "S2: " << secret_key2 << std::endl << "P2: " << public_key2 << std::endl;

    // save these for later
    crypto_public_key_t public_ephemeral;

    crypto_scalar_t secret_ephemeral;

    crypto_key_image_t key_image, key_image2;

    {
        std::cout << std::endl << "Stealth Checks..." << std::endl;

        std::cout << std::endl << "Sender..." << std::endl;

        const auto derivation = Crypto::generate_key_derivation(public_key2, secret_key);

        std::cout << "generate_key_derivation: " << derivation << std::endl;

        const auto derivation_scalar = Crypto::derivation_to_scalar(derivation, 64);

        std::cout << "derivation_to_scalar: " << derivation_scalar << std::endl;

        const auto expected_public_ephemeral = Crypto::derive_public_key(derivation_scalar, public_key2);

        std::cout << "derive_public_key: " << expected_public_ephemeral << std::endl;

        std::cout << std::endl << "Receiver..." << std::endl;

        const auto derivation2 = Crypto::generate_key_derivation(public_key, secret_key2);

        std::cout << "generate_key_derivation: " << derivation2 << std::endl;

        const auto derivation_scalar2 = Crypto::derivation_to_scalar(derivation2, 64);

        std::cout << "derivation_to_scalar: " << derivation_scalar2 << std::endl;

        public_ephemeral = Crypto::derive_public_key(derivation_scalar2, public_key2);

        std::cout << "derive_public_key: " << public_ephemeral << std::endl;

        secret_ephemeral = Crypto::derive_secret_key(derivation_scalar2, secret_key2);

        std::cout << "derive_secret_key: " << secret_ephemeral << std::endl;

        {
            const auto check = secret_ephemeral.point();

            if (check != expected_public_ephemeral)
            {
                std::cout << "public_ephemeral does not match expected value" << std::endl;

                return 1;
            }
        }

        // check underive_public_key
        {
            const auto underived_public_key = Crypto::underive_public_key(derivation, 64, public_ephemeral);

            std::cout << "underive_public_key: " << underived_public_key << std::endl;

            if (underived_public_key != public_key2)
            {
                std::cout << "underived_public_key does not match expected value" << std::endl;

                return 1;
            }
        }

        key_image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

        if (!key_image.check_subgroup())
        {
            std::cout << "Invalid Key Image!" << std::endl;

            return 1;
        }

        std::cout << "generate_key_image: " << key_image << std::endl;

        key_image2 = Crypto::generate_key_image_v2(secret_ephemeral);

        if (!key_image2.check_subgroup())
        {
            std::cout << "Invalid Key Image!" << std::endl;

            return 1;
        }

        std::cout << "generate_key_image_v2: " << key_image2 << std::endl;
    }

    // Audit Output Proofs
    {
        std::cout << std::endl << std::endl << "Audit Output Proofs" << std::endl;

        const auto [public_keys, secret_keys] = Crypto::generate_keys_m(20);

        const auto [success, proof] = Crypto::Audit::generate_outputs_proof(secret_keys);

        if (success)
        {
            std::cout << "Audit::generate_outputs_proof: Passed!" << std::endl;
        }
        else
        {
            std::cout << "Audit::generate_outputs_proof: Failed!" << std::endl;

            return 1;
        }

        std::cout << std::endl << proof << std::endl << std::endl;

        const auto [valid, key_images] = Crypto::Audit::check_outputs_proof(public_keys, proof);

        if (valid)
        {
            std::cout << "Audit::check_outputs_proof: Passed!" << std::endl;
        }
        else
        {
            std::cout << "Audit::check_outputs_proof: Failed!" << std::endl;

            return 1;
        }
    }

    // Single Signature
    {
        std::cout << std::endl << std::endl << "Message Signing" << std::endl;

        const auto signature = Crypto::Signature::generate_signature(SHA3_HASH, secret_key);

        std::cout << "Signature::generate_signature: Passed!" << std::endl;

        if (!Crypto::Signature::check_signature(SHA3_HASH, public_key, signature))
        {
            std::cout << "Signature::check_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Signature::check_signature: Passed!" << std::endl;
    }

    // RFC8032 Signature
    {
        std::cout << std::endl << std::endl << "Message Signing RFC-8032" << std::endl;

        const auto signature = Crypto::RFC8032::generate_signature(SHA3_HASH, secret_key);

        std::cout << "RFC8032::generate_signature: Passed!" << std::endl;

        if (!Crypto::RFC8032::check_signature(SHA3_HASH, public_key, signature))
        {
            std::cout << "RFC8032::check_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "RFC8032::check_signature: Passed!" << std::endl;
    }

    // Borromean
    {
        std::cout << std::endl << std::endl << "Borromean Ring Signature" << std::endl;

        auto public_keys = crypto_point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto [gen_success, signature] =
            Crypto::RingSignature::Borromean::generate_ring_signature(SHA3_HASH, secret_ephemeral, public_keys);

        if (!gen_success)
        {
            std::cout << "Borromean::generate_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Borromean::generate_ring_signature: Passed!" << std::endl;

        std::cout << signature << std::endl;

        std::cout << signature.to_string() << std::endl << std::endl;

        if (!Crypto::RingSignature::Borromean::check_ring_signature(SHA3_HASH, key_image, public_keys, signature))
        {
            std::cout << "Borromean::check_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Borromean::check_ring_signature: Passed!" << std::endl;

        if (!test_binary_encoding_v2(signature))
        {
            std::cout << "Borromean binary encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Borromean binary encoding check: Passed!" << std::endl;
        }

        if (!test_json_encoding(signature))
        {
            std::cout << "Borromean JSON encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Borromean JSON encoding check: Passed!" << std::endl;
        }
    }

    // CLSAG
    {
        std::cout << std::endl << std::endl << "CLSAG Ring Signature" << std::endl;

        auto public_keys = crypto_point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto [gen_sucess, signature] =
            Crypto::RingSignature::CLSAG::generate_ring_signature(SHA3_HASH, secret_ephemeral, public_keys);

        if (!gen_sucess)
        {
            std::cout << "CLSAG::generate_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "CLSAG::generate_ring_signature: Passed!" << std::endl;

        std::cout << signature << std::endl;

        std::cout << signature.to_string() << std::endl << std::endl;

        if (!Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, key_image, public_keys, signature))
        {
            std::cout << "CLSAG::check_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "CLSAG::check_ring_signature: Passed!" << std::endl;

        if (!test_binary_encoding(signature))
        {
            std::cout << "CLSAG binary encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "CLSAG binary encoding check: Passed!" << std::endl;
        }

        if (!test_json_encoding(signature))
        {
            std::cout << "CLSAG JSON encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "CLSAG JSON encoding check: Passed!" << std::endl;
        }
    }

    // CLSAG w/ Commitments
    {
        std::cout << std::endl << std::endl << "CLSAG Ring Signature w/ Commitments" << std::endl;

        auto public_keys = crypto_point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto input_blinding = crypto_scalar_t::random();

        const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

        std::vector<crypto_pedersen_commitment_t> public_commitments = crypto_point_t::random(RING_SIZE);

        public_commitments[RING_SIZE / 2] = input_commitment;

        const auto [ps_blindings, ps_commitments] =
            Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));

        const auto [gen_sucess, signature] = Crypto::RingSignature::CLSAG::generate_ring_signature(
            SHA3_HASH,
            secret_ephemeral,
            public_keys,
            input_blinding,
            public_commitments,
            ps_blindings[0],
            ps_commitments[0]);

        if (!gen_sucess)
        {
            std::cout << "CLSAG::generate_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "CLSAG::generate_ring_signature: Passed!" << std::endl;

        std::cout << signature << std::endl;

        std::cout << signature.to_string() << std::endl << std::endl;

        if (!Crypto::RingSignature::CLSAG::check_ring_signature(
                SHA3_HASH, key_image, public_keys, signature, public_commitments))
        {
            std::cout << "CLSAG::check_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "CLSAG::check_ring_signature: Passed!" << std::endl;

        if (!test_binary_encoding(signature))
        {
            std::cout << "CLSAG binary encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "CLSAG binary encoding check: Passed!" << std::endl;
        }

        if (!test_json_encoding(signature))
        {
            std::cout << "CLSAG JSON encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "CLSAG JSON encoding check: Passed!" << std::endl;
        }
    }

    // Triptych
    {
        std::cout << std::endl << std::endl << "Triptych Ring Signature" << std::endl;

        auto public_keys = crypto_point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto input_blinding = crypto_scalar_t::random();

        const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

        std::vector<crypto_pedersen_commitment_t> public_commitments = crypto_point_t::random(RING_SIZE);

        public_commitments[RING_SIZE / 2] = input_commitment;

        const auto [ps_blindings, ps_commitments] =
            Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));

        const auto [gen_sucess, signature] = Crypto::RingSignature::Triptych::generate_ring_signature(
            SHA3_HASH,
            secret_ephemeral,
            public_keys,
            input_blinding,
            public_commitments,
            ps_blindings[0],
            ps_commitments[0]);

        if (!gen_sucess)
        {
            std::cout << "Triptych::generate_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Triptych::generate_ring_signature: Passed!" << std::endl;

        std::cout << signature << std::endl;

        std::cout << signature.to_string() << std::endl << std::endl;

        if (!Crypto::RingSignature::Triptych::check_ring_signature(
                SHA3_HASH, key_image2, public_keys, signature, public_commitments))
        {
            std::cout << "Triptych::check_ring_signature: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Triptych::check_ring_signature: Passed!" << std::endl;

        if (!test_binary_encoding(signature))
        {
            std::cout << "Triptych binary encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Triptych binary encoding check: Passed!" << std::endl;
        }

        if (!test_json_encoding(signature))
        {
            std::cout << "Triptych JSON encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Triptych JSON encoding check: Passed!" << std::endl;
        }
    }

    // RingCT Basics
    {
        std::cout << std::endl << std::endl << "RingCT" << std::endl;

        /**
         * Generate two random scalars, and then feed them to our blinding factor
         * generator -- normally these are computed based on the derivation scalar
         * calculated for the destination one-time key
         */
        auto blinding_factors = crypto_scalar_t::random(2);

        for (auto &factor : blinding_factors)
        {
            factor = Crypto::RingCT::generate_commitment_blinding_factor(factor);
        }

        /**
         * Generate two fake output commitments using the blinding factors calculated above
         */
        const auto C_1 = Crypto::RingCT::generate_pedersen_commitment(blinding_factors[0], 1000);

        const auto C_2 = Crypto::RingCT::generate_pedersen_commitment(blinding_factors[1], 1000);

        // Generate the pedersen commitment for the transaction fee with a ZERO blinding factor
        const auto C_fee = Crypto::RingCT::generate_pedersen_commitment({0}, 100);

        std::cout << "RingCT::generate_pedersen_commitment:" << std::endl
                  << "\t" << C_1 << std::endl
                  << "\t" << C_2 << std::endl
                  << "\t" << C_fee << std::endl;

        /**
         * Add up the commitments of the "real" output commitments plus
         * the commitment to the transaction fee
         */
        const auto CT = C_1 + C_2 + C_fee;

        /**
         * Generate the pseudo output commitments and blinding factors
         */
        const auto [pseudo_blinding_factors, pseudo_commitments] =
            Crypto::RingCT::generate_pseudo_commitments({2000, 100}, blinding_factors);

        std::cout << std::endl << "RingCT::generate_pseudo_commitments:" << std::endl;

        for (const auto &commitment : pseudo_commitments)
            std::cout << "\t" << commitment << std::endl;

        std::cout << std::endl;

        // Add all of the pseudo commitments together
        const auto PT = crypto_point_vector_t(pseudo_commitments).sum();

        // And check that they match the total from the "real" output commitments
        if (PT != CT)
        {
            std::cout << "RingCT::generate_pseudo_commitments: Failed!" << std::endl;

            return 1;
        }

        std::cout << "RingCT::generate_pseudo_commitments: Passed!" << std::endl;

        if (!Crypto::RingCT::check_commitments_parity(pseudo_commitments, {C_1, C_2}, 100))
        {
            std::cout << "RingCT::check_commitments_parity: Failed!" << std::endl;

            return 1;
        }

        std::cout << "RingCT::check_commitments_parity: Passed!" << std::endl;

        const auto derivation_scalar = crypto_scalar_t::random();

        // amount masking (hiding)
        {
            const auto amount_mask = Crypto::RingCT::generate_amount_mask(derivation_scalar);

            const crypto_scalar_t amount = crypto_scalar_t(13371337);

            const auto masked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, amount);

            const auto unmasked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, masked_amount);

            if (masked_amount.to_uint64_t() == amount.to_uint64_t()
                || unmasked_amount.to_uint64_t() != amount.to_uint64_t())
            {
                std::cout << "RingCT::toggle_masked_amount: Failed!" << std::endl;

                return 1;
            }

            std::cout << "RingCT::toggle_masked_amount: Passed!" << std::endl;
        }
    }

    // Bulletproofs
    {
        std::cout << std::endl << std::endl << "Bulletproofs" << std::endl;

        auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove({1000}, crypto_scalar_t::random(1));

        if (!Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}))
        {
            std::cout << "Crypto::RangeProofs::Bulletproofs[1]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::RangeProofs::Bulletproofs[1]: Passed!" << std::endl;

        std::cout << proof << std::endl;

        std::cout << proof.to_string() << std::endl << std::endl;

        proof.taux *= Crypto::TWO;

        if (Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}))
        {
            std::cout << "Crypto::RangeProofs::Bulletproofs[2]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::RangeProofs::Bulletproofs[2]: Passed!" << std::endl;

        // verify that value out of range fails proof
        auto [proof2, commitments2] = Crypto::RangeProofs::Bulletproofs::prove({1000}, crypto_scalar_t::random(1), 8);

        if (Crypto::RangeProofs::Bulletproofs::verify({proof2}, {commitments2}, 8))
        {
            std::cout << "Crypto::RangeProofs::Bulletproofs[3]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::RangeProofs::Bulletproofs[3]: Passed!" << std::endl;

        if (!test_binary_encoding(proof))
        {
            std::cout << "Bulletproofs binary encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Bulletproofs binary encoding check: Passed!" << std::endl;
        }

        if (!test_json_encoding(proof))
        {
            std::cout << "Bulletproofs JSON encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Bulletproofs JSON encoding check: Passed!" << std::endl;
        }
    }

    // Bulletproofs+
    {
        std::cout << std::endl << std::endl << "Bulletproofs+" << std::endl;

        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, crypto_scalar_t::random(1));

        if (!Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}))
        {
            std::cout << "Crypto::RangeProofs::BulletproofsPlus[1]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::RangeProofs::BulletproofsPlus[1]: Passed!" << std::endl;

        std::cout << proof << std::endl;

        std::cout << proof.to_string() << std::endl << std::endl;

        proof.d1 *= Crypto::TWO;

        if (Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}))
        {
            std::cout << "Crypto::RangeProofs::BulletproofsPlus[2]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::RangeProofs::BulletproofsPlus[2]: Passed!" << std::endl;

        // verify that value out of range fails proof
        auto [proof2, commitments2] =
            Crypto::RangeProofs::BulletproofsPlus::prove({1000}, crypto_scalar_t::random(1), 8);

        if (Crypto::RangeProofs::BulletproofsPlus::verify({proof2}, {commitments2}, 8))
        {
            std::cout << "Crypto::RangeProofs::BulletproofsPlus[3]: Failed!" << std::endl;

            return 1;
        }

        std::cout << "Crypto::RangeProofs::BulletproofsPlus[3]: Passed!" << std::endl;

        if (!test_binary_encoding(proof))
        {
            std::cout << "Bulletproofs+ binary encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Bulletproofs+ binary encoding check: Passed!" << std::endl;
        }

        if (!test_json_encoding(proof))
        {
            std::cout << "Bulletproofs+ JSON encoding check: Failed!" << std::endl;

            return 1;
        }
        else
        {
            std::cout << "Bulletproofs+ JSON encoding check: Passed!" << std::endl;
        }
    }

    // Benchmarks
    {
        std::cout << std::endl << std::endl << std::endl;

        benchmark_header();

        const auto [point, scalar] = Crypto::generate_keys();

        const auto ds = Crypto::derivation_to_scalar(point, 64);

        key_image = Crypto::generate_key_image(point, scalar);

        benchmark(
            []() { crypto_hash_t::sha3(INPUT_DATA); }, "crypto_hash_t::sha3", BENCHMARK_PERFORMANCE_ITERATIONS_LONG);

        benchmark(
            []() { crypto_hash_t::blake2b(INPUT_DATA); },
            "crypto_hash_t::blake2b",
            BENCHMARK_PERFORMANCE_ITERATIONS_LONG);

        benchmark([]() { crypto_hash_t::argon2d(INPUT_DATA, 4, 256, 1); }, "crypto_hash_t::argon2d");

        benchmark([]() { crypto_hash_t::argon2i(INPUT_DATA, 4, 256, 1); }, "crypto_hash_t::argon2i");

        benchmark([]() { crypto_hash_t::argon2id(INPUT_DATA, 4, 256, 1); }, "crypto_hash_t::argon2id");

        std::cout << std::endl;

        benchmark([]() { crypto_entropy_t::random(); }, "crypto_entropy_t::random()");

        benchmark([]() { const auto hash = crypto_hash_t::random(); }, "crypto_hash_t::random()");

        benchmark([]() { const auto [point, scalar] = Crypto::generate_keys(); }, "random_keys()");

        benchmark(
            [&point = point]() { const auto base58 = Crypto::Base58::encode(point.serialize()); },
            "Crypto::Base58::encode()");

        const auto encoded = Crypto::Base58::encode(point.serialize());

        benchmark(
            [&encoded = encoded]() { const auto [succes, reader] = Crypto::Base58::decode(encoded); },
            "Crypto::Base58::decode()");

        std::cout << std::endl;

        benchmark(
            [&point = point, &scalar = scalar]() { Crypto::generate_key_derivation(point, scalar); },
            "Crypto::generate_key_derivation");

        benchmark([&ds, &point = point]() { Crypto::derive_public_key(ds, point); }, "Crypto::derive_public_key");

        benchmark([&ds, &scalar = scalar]() { Crypto::derive_secret_key(ds, scalar); }, "Crypto::derive_secret_key");

        benchmark([&point = point]() { Crypto::underive_public_key(point, 64, point); }, "Crypto::underive_public_key");

        benchmark(
            [&point = point, &scalar = scalar]() { Crypto::generate_key_image(point, scalar); },
            "Crypto::generate_key_image");

        benchmark(
            [&key_image]() { const auto valid = key_image.check_subgroup(); }, "crypto_point_t::check_subgroup()");

        // signing
        {
            crypto_signature_t sig;

            std::cout << std::endl;

            benchmark(
                [&sig, &scalar = scalar]() { sig = Crypto::Signature::generate_signature(SHA3_HASH, scalar); },
                "Crypto::Signature::generate_signature");

            benchmark(
                [&sig, &point = point]() { Crypto::Signature::check_signature(SHA3_HASH, point, sig); },
                "Crypto::Signature::check_signature");
        }

        // signing RF8032
        {
            crypto_signature_t sig;

            std::cout << std::endl;

            benchmark(
                [&sig, &scalar = scalar]() { sig = Crypto::RFC8032::generate_signature(SHA3_HASH, scalar); },
                "Crypto::RFC8032::generate_signature");

            benchmark(
                [&sig, &point = point]() { Crypto::RFC8032::check_signature(SHA3_HASH, point, sig); },
                "Crypto::RFC8032::check_signature");
        }

        // Borromean
        {
            auto public_keys = crypto_point_t::random(RING_SIZE);

            public_keys[RING_SIZE / 2] = public_ephemeral;

            crypto_borromean_signature_t signature;

            const auto image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

            std::cout << std::endl;

            benchmark(
                [&public_keys, &secret_ephemeral, &signature]()
                {
                    const auto [succes, sigs] = Crypto::RingSignature::Borromean::generate_ring_signature(
                        SHA3_HASH, secret_ephemeral, public_keys);
                    signature = sigs;
                },
                "Crypto::RingSignature::Borromean::generate_ring_signature",
                100);

            benchmark(
                [&public_keys, &image, &signature]()
                { Crypto::RingSignature::Borromean::check_ring_signature(SHA3_HASH, image, public_keys, signature); },
                "Crypto::RingSignature::Borromean::check_ring_signature",
                100);
        }

        // CLSAG
        {
            auto public_keys = crypto_point_t::random(RING_SIZE);

            public_keys[RING_SIZE / 2] = public_ephemeral;

            crypto_clsag_signature_t signature;

            const auto image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

            std::cout << std::endl;

            benchmark(
                [&public_keys, &secret_ephemeral, &signature]()
                {
                    const auto [success, sig] =
                        Crypto::RingSignature::CLSAG::generate_ring_signature(SHA3_HASH, secret_ephemeral, public_keys);
                    signature = sig;
                },
                "Crypto::RingSignature::CLSAG::generate_ring_signature",
                100);

            benchmark(
                [&public_keys, &image, &signature]()
                { Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, image, public_keys, signature); },
                "Crypto::RingSignature::CLSAG::check_ring_signature",
                100);
        }

        // CLSAG w/ Commitments
        {
            auto public_keys = crypto_point_t::random(RING_SIZE);

            public_keys[RING_SIZE / 2] = public_ephemeral;

            crypto_clsag_signature_t signature;

            const auto image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

            const auto input_blinding = crypto_scalar_t::random();

            const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

            std::vector<crypto_pedersen_commitment_t> public_commitments = crypto_point_t::random(RING_SIZE);

            public_commitments[RING_SIZE / 2] = input_commitment;

            const auto [ps_blindings, ps_commitments] =
                Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));

            std::cout << std::endl;

            benchmark(
                [&public_keys,
                 &secret_ephemeral,
                 &signature,
                 &input_blinding,
                 &public_commitments,
                 &ps_blindings = ps_blindings,
                 &ps_commitments = ps_commitments]()
                {
                    const auto [success, sig] = Crypto::RingSignature::CLSAG::generate_ring_signature(
                        SHA3_HASH,
                        secret_ephemeral,
                        public_keys,
                        input_blinding,
                        public_commitments,
                        ps_blindings[0],
                        ps_commitments[0]);
                    signature = sig;
                },
                "Crypto::RingSignature::CLSAG::generate_ring_signature[commitments]",
                100);

            benchmark(
                [&public_keys, &image, &signature, &public_commitments]() {
                    Crypto::RingSignature::CLSAG::check_ring_signature(
                        SHA3_HASH, image, public_keys, signature, public_commitments);
                },
                "Crypto::RingSignature::CLSAG::check_ring_signature[commitments]",
                100);
        }

        // Triptych
        {
            auto public_keys = crypto_point_t::random(RING_SIZE);

            public_keys[RING_SIZE / 2] = public_ephemeral;

            crypto_triptych_signature_t signature;

            const auto image = Crypto::generate_key_image_v2(secret_ephemeral);

            const auto input_blinding = crypto_scalar_t::random();

            const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

            std::vector<crypto_pedersen_commitment_t> public_commitments = crypto_point_t::random(RING_SIZE);

            public_commitments[RING_SIZE / 2] = input_commitment;

            const auto [ps_blindings, ps_commitments] =
                Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));

            std::cout << std::endl;

            benchmark(
                [&public_keys,
                 &secret_ephemeral,
                 &signature,
                 &input_blinding,
                 &public_commitments,
                 &ps_blindings = ps_blindings,
                 &ps_commitments = ps_commitments]()
                {
                    const auto [success, sig] = Crypto::RingSignature::Triptych::generate_ring_signature(
                        SHA3_HASH,
                        secret_ephemeral,
                        public_keys,
                        input_blinding,
                        public_commitments,
                        ps_blindings[0],
                        ps_commitments[0]);
                    signature = sig;
                },
                "Crypto::RingSignature::Triptych::generate_ring_signature",
                100);

            benchmark(
                [&public_keys, &image, &signature, &public_commitments]()
                {
                    Crypto::RingSignature::Triptych::check_ring_signature(
                        SHA3_HASH, image, public_keys, signature, public_commitments);
                },
                "Crypto::RingSignature::Triptych::check_ring_signature",
                100);
        }

        // RingCT
        {
            const auto blinding_factor = crypto_scalar_t::random();

            std::cout << std::endl;

            benchmark(
                [&blinding_factor]() { Crypto::RingCT::generate_pedersen_commitment(blinding_factor, 10000); },
                "Crypto::RingCT::generate_pedersen_commitment");

            benchmark(
                [&blinding_factor]() { Crypto::RingCT::generate_pseudo_commitments({10000}, {blinding_factor}); },
                "Crypto::RingCT::generate_pseudo_commitments");
        }

        // Bulletproofs
        {
            const auto blinding_factors = crypto_scalar_t::random(1);

            // seed the memory cache as to not taint the benchmark
            const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove({1000}, blinding_factors);

            crypto_bulletproof_t proof;

            std::vector<crypto_pedersen_commitment_t> commitments;

            std::cout << std::endl;

            benchmark(
                [&proof, &blinding_factors, &commitments]()
                {
                    const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove({1000}, blinding_factors);
                    proof = p;
                    commitments = c;
                },
                "Crypto::RangeProofs::Bulletproofs::prove",
                10);

            benchmark(
                [&proof, &commitments]() { Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}); },
                "Crypto::RangeProofs::Bulletproofs::verify",
                10);

            benchmark(
                [&proof, &commitments]() {
                    Crypto::RangeProofs::Bulletproofs::verify({proof, proof}, {commitments, commitments});
                },
                "Crypto::RangeProofs::Bulletproofs::verify[batched]",
                10);
        }

        // Bulletproofs+
        {
            const auto blinding_factors = crypto_scalar_t::random(1);

            // seed the memory cache as to not taint the benchmark
            const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, blinding_factors);

            crypto_bulletproof_plus_t proof;

            std::vector<crypto_pedersen_commitment_t> commitments;

            std::cout << std::endl;

            benchmark(
                [&proof, &blinding_factors, &commitments]()
                {
                    const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, blinding_factors);
                    proof = p;
                    commitments = c;
                },
                "Crypto::RangeProofs::BulletproofsPlus::prove",
                10);

            benchmark(
                [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}); },
                "Crypto::RangeProofs::BulletproofsPlus::verify",
                10);

            benchmark(
                [&proof, &commitments]() {
                    Crypto::RangeProofs::BulletproofsPlus::verify({proof, proof}, {commitments, commitments});
                },
                "Crypto::RangeProofs::BulletproofsPlus::verify[batched]",
                10);
        }

        std::cout << std::endl << std::endl;

        // Complex Benchmark
        {
            benchmark(
                []()
                {
                    const auto [public_key, secret_key] = Crypto::generate_keys();

                    const auto encoded = Crypto::Base58::encode(public_key.serialize());

                    const auto hash = crypto_hash_t::sha3(encoded);

                    const auto zeros = hash.hex_leading_zeros();
                },
                "Complex Benchmark");
        }
    }

    return 0;
}
