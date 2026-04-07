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

#include <crypto.h>
#include <cstring>
#include <functional>

#define RING_SIZE 4

const hash_t INPUT_DATA = {0xcf, 0xc7, 0x65, 0xd9, 0x05, 0xc6, 0x5e, 0x2b, 0x61, 0x81, 0x6d,
                           0xc1, 0xf0, 0xfd, 0x69, 0xf6, 0xf6, 0x77, 0x9f, 0x36, 0xed, 0x62,
                           0x39, 0xac, 0x7e, 0x21, 0xff, 0x51, 0xef, 0x2c, 0x89, 0x1e};

const hash_t SHA3_HASH = {0x97, 0x45, 0x06, 0x60, 0x1a, 0x60, 0xdc, 0x46, 0x5e, 0x6e, 0x9a,
                          0xcd, 0xdb, 0x56, 0x38, 0x89, 0xe6, 0x34, 0x71, 0x84, 0x9e, 0xc4,
                          0x19, 0x86, 0x56, 0x55, 0x03, 0x54, 0xb8, 0x54, 0x1f, 0xcb};

const auto SHA3_SLOW_0 = hash_t("974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb");

const auto SHA3_SLOW_4096 = hash_t("c031be420e429992443c33c2a453287e2678e70b8bce95dfe7357bcbf36ca86c");

const auto BLAKE2B = hash_t("56a8ef7f9d7db21fa29b83eb77551f0c3e312525d6151946261911fc38a508c4");

const auto ARGON2D_4_1024_1 = hash_t("cd65323e3e56272fd19b745b0673318b21c2be5257f918267998b341719c3d5a");

const auto ARGON2I_4_1024_1 = hash_t("debb2a3b51732bff26670753c5dbaedf6139c177108fe8e0744305c8d410a75a");

const auto ARGON2ID_4_1024_1 = hash_t("a6ac954bce48a46bc01a9b16b484ffb745401ae421b1b6f2e22cf474d4cac1c9");

const uint64_t BASE58_PREFIX = 0x106a1c;

template<typename T> static inline bool test_binary_encoding(const T &value)
{
    Serialization::serializer_t writer;

    value.serialize(writer);

    Serialization::deserializer_t reader(writer);

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

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static bool check(const char *name, bool condition)
{
    ++tests_run;

    if (condition)
    {
        ++tests_passed;
        std::cout << "  PASS: " << name << std::endl;
        return true;
    }

    ++tests_failed;
    std::cout << "  FAIL: " << name << std::endl;
    return false;
}

static bool has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], flag) == 0)
            return true;
    }

    return false;
}

int main(int argc, char **argv)
{
    std::cout << std::endl << "Crypto Unit Tests" << std::endl;
    std::cout << "==================" << std::endl;

    if (has_flag(argc, argv, "--autotune"))
    {
        std::cout << "Running autotune..." << std::flush;
        Crypto::autotune();
        std::cout << " done." << std::endl;
    }
    else if (has_flag(argc, argv, "--init"))
    {
        std::cout << "Running init (heuristic dispatch)..." << std::flush;
        Crypto::init();
        std::cout << " done." << std::endl;
    }

    std::cout << std::endl << "=== Sanity Checks ===" << std::endl;

    {
        const auto point = point_t();

        if (!check("point_t empty", point.empty()))
            return 1;

        const auto scalar = scalar_t();

        if (!check("scalar_t empty", scalar.empty()))
            return 1;

        const auto signature = signature_t();

        if (!check("signature_t empty", signature.empty()))
            return 1;

        const auto hash = hash_t();

        if (!check("hash_t empty", hash.empty()))
            return 1;

        const auto entropy = entropy_t();

        if (!check("entropy_t empty", entropy.empty()))
            return 1;
    }

    std::cout << std::endl << "=== Hashing ===" << std::endl;

    std::cout << "    random hash: " << hash_t::random() << std::endl;
    std::cout << "    input data:  " << INPUT_DATA << std::endl;

    // SHA-3 test
    {
        const auto hash = hash_t::sha3(INPUT_DATA);

        std::cout << "    sha3: " << hash << std::endl << std::endl;

        if (!check("sha3", hash == SHA3_HASH))
            return 1;
    }

    // Blake2b Test
    {
        const auto hash = hash_t::blake2b(INPUT_DATA);

        std::cout << "    blake2b: " << hash << std::endl << std::endl;

        if (!check("blake2b", hash == BLAKE2B))
            return 1;
    }

    // Argon2d Test
    {
        const auto hash = hash_t::argon2d(INPUT_DATA, 4, 1024, 1);

        std::cout << "    argon2d: " << hash << std::endl << std::endl;

        if (!check("argon2d", hash == ARGON2D_4_1024_1))
            return 1;
    }

    // Argon2i Test
    {
        const auto hash = hash_t::argon2i(INPUT_DATA, 4, 1024, 1);

        std::cout << "    argon2i: " << hash << std::endl << std::endl;

        if (!check("argon2i", hash == ARGON2I_4_1024_1))
            return 1;
    }

    // Argon2id Test
    {
        const auto hash = hash_t::argon2id(INPUT_DATA, 4, 1024, 1);

        std::cout << "    argon2id: " << hash << std::endl << std::endl;

        if (!check("argon2id", hash == ARGON2ID_4_1024_1))
            return 1;
    }

    // SHA-3 slow hash
    {
        auto hash = hash_t::sha3_slow(INPUT_DATA);

        std::cout << "    sha3_slow: " << hash << std::endl << std::endl;

        if (!check("sha3_slow", hash == SHA3_SLOW_0))
            return 1;

        hash = hash_t::sha3_slow(INPUT_DATA, 4096);

        std::cout << "    sha3_slow[4096]: " << hash << std::endl << std::endl;

        if (!check("sha3_slow[4096]", hash == SHA3_SLOW_4096))
            return 1;
    }

    std::cout << std::endl << "=== AES ===" << std::endl;

    // AES Test
    {
        const auto input = std::string("cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e");

        std::cout << "    input:     " << input << std::endl;

        const auto password = std::string("SuperSecretPassword");

        std::cout << "    password:  " << password << std::endl;

        const auto encrypted = Crypto::AES::encrypt(input, password);

        std::cout << "    encrypted: " << encrypted << std::endl;

        const auto decrypted = Crypto::AES::decrypt(encrypted, password);

        std::cout << "    decrypted: " << decrypted << std::endl << std::endl;

        if (!check("aes encrypt/decrypt", decrypted == input))
            return 1;
    }

    std::cout << std::endl << "=== Base58 ===" << std::endl;

    // Base58 Test #1
    {
        const auto a = point_t::random();

        const auto b = point_t::random();

        Serialization::serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::Base58::encode(writer.vector());

        std::cout << "    raw:     " << writer.to_string() << std::endl;
        std::cout << "    encoded: " << encoded << std::endl << std::endl;

        auto [success, reader] = Crypto::Base58::decode(encoded);

        if (!success)
        {
            check("base58 decode", false);
            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<point_t>();

        const auto checkb = reader.pod<point_t>();

        if (!check("base58 encode/decode", checka == a && checkb == b && prefix == BASE58_PREFIX))
            return 1;
    }

    // Base58 Test #2
    {
        const auto a = point_t::random();

        const auto b = point_t::random();

        Serialization::serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::Base58::encode_check(writer);

        std::cout << "    raw:     " << writer.to_string() << std::endl;
        std::cout << "    encoded: " << encoded << std::endl << std::endl;

        auto [success, reader] = Crypto::Base58::decode_check(encoded);

        if (!success)
        {
            check("base58 decode_check", false);
            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<point_t>();

        const auto checkb = reader.pod<point_t>();

        if (!check("base58 encode_check/decode_check", checka == a && checkb == b && prefix == BASE58_PREFIX))
            return 1;
    }

    // CryptoNote Base58 Test #1
    {
        const auto a = point_t::random();

        const auto b = point_t::random();

        Serialization::serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::CNBase58::encode_check(writer);

        std::cout << "    raw:     " << writer.to_string() << std::endl;
        std::cout << "    encoded: " << encoded << std::endl << std::endl;

        auto [success, reader] = Crypto::CNBase58::decode(encoded);

        if (!success)
        {
            check("cnbase58 decode", false);
            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<point_t>();

        const auto checkb = reader.pod<point_t>();

        if (!check("cnbase58 encode/decode", checka == a && checkb == b && prefix == BASE58_PREFIX))
            return 1;
    }

    // CryptoNote Base58 Test #2
    {
        const auto a = point_t::random();

        const auto b = point_t::random();

        Serialization::serializer_t writer;

        writer.varint(BASE58_PREFIX);

        writer.pod(a);

        writer.pod(b);

        const auto encoded = Crypto::CNBase58::encode_check(writer);

        std::cout << "    raw:     " << writer.to_string() << std::endl;
        std::cout << "    encoded: " << encoded << std::endl << std::endl;

        auto [success, reader] = Crypto::CNBase58::decode_check(encoded);

        if (!success)
        {
            check("cnbase58 decode_check", false);
            return 1;
        }

        const auto prefix = reader.varint<uint64_t>();

        const auto checka = reader.pod<point_t>();

        const auto checkb = reader.pod<point_t>();

        if (!check("cnbase58 encode_check/decode_check", checka == a && checkb == b && prefix == BASE58_PREFIX))
            return 1;
    }

    std::cout << std::endl << "=== Utilities ===" << std::endl;

    // 2^n rounding test
    {
        const auto val = Crypto::pow2_round(13);

        if (!check("pow2_round", val == 16))
            return 1;
    }

    // check for randomness
    {
        const auto points = point_vector_t(point_t::random(20)).dedupe_sort();

        if (!check("random points unique", points.size() == 20))
            return 1;

        const auto scalars = scalar_vector_t(scalar_t::random(20)).dedupe_sort();

        if (!check("random scalars unique", scalars.size() == 20))
            return 1;
    }

    // check tests
    {
        const auto scalar = std::string("a03681f038b1aee4d417874fa551aaa8f4a608a70ddff0257dd93f932b8fef0e");

        const auto point = std::string("d555bf22bce71d4eff27aa7597b5590969e7eccdb67a52188d0d73d5ab82d414");

        if (!check("check_scalar valid", Crypto::check_scalar(scalar)))
            return 1;

        if (!check("check_scalar rejects point", !Crypto::check_scalar(point)))
            return 1;

        if (!check("check_point valid", Crypto::check_point(point)))
            return 1;

        if (!check("check_point rejects scalar", !Crypto::check_point(scalar)))
            return 1;
    }

    // Scalar bit vector test
    {
        const auto a = scalar_t::random();

        const auto bits = a.to_bits();

        scalar_t b(bits);

        if (!check("scalar bit vector roundtrip", b == a))
            return 1;
    }

    std::cout << std::endl << "=== Entropy ===" << std::endl;

    // Entropy Tests
    {
        const auto wallet_entropy = entropy_t::random(256, {});

        std::cout << "    entropy:   " << wallet_entropy << std::endl;
        std::cout << "    mnemonic:  " << wallet_entropy.to_mnemonic_phrase() << std::endl;
        std::cout << "    timestamp: " << wallet_entropy.timestamp() << std::endl;

        const auto wallet_entropy_2 = entropy_t::recover(wallet_entropy.to_mnemonic_phrase());

        std::cout << "    restored:  " << wallet_entropy_2 << std::endl;
        std::cout << "    mnemonic:  " << wallet_entropy_2.to_mnemonic_phrase() << std::endl;
        std::cout << "    timestamp: " << wallet_entropy_2.timestamp() << std::endl << std::endl;

        if (!check("entropy 256-bit restore", wallet_entropy_2 == wallet_entropy))
            return 1;
    }

    {
        const auto wallet_entropy = entropy_t::random(128, {}, false);

        std::cout << "    entropy:   " << wallet_entropy << std::endl;
        std::cout << "    mnemonic:  " << wallet_entropy.to_mnemonic_phrase() << std::endl;
        std::cout << "    timestamp: " << wallet_entropy.timestamp() << std::endl;

        const auto wallet_entropy_2 = entropy_t::recover(wallet_entropy.to_mnemonic_phrase());

        std::cout << "    restored:  " << wallet_entropy_2 << std::endl;
        std::cout << "    mnemonic:  " << wallet_entropy_2.to_mnemonic_phrase() << std::endl;
        std::cout << "    timestamp: " << wallet_entropy_2.timestamp() << std::endl << std::endl;

        if (!check("entropy 128-bit restore", wallet_entropy_2 == wallet_entropy))
            return 1;
    }

    std::cout << std::endl << "=== Key Derivation ===" << std::endl;

    const auto wallet_entropy = entropy_t::random();

    std::cout << "    entropy: " << wallet_entropy << std::endl;

    const auto seed = seed_t(wallet_entropy);

    std::cout << "    seed:    " << seed << std::endl;

    const auto [public_key, secret_key] = seed.generate_child_key(44, 0, 0, 0, 0).keys();

    std::cout << "    secret:  " << secret_key << std::endl;
    std::cout << "    public:  " << public_key << std::endl << std::endl;

    {
        const auto check_key = secret_key.point();

        if (!check("secret_key_to_public_key", check_key == public_key))
            return 1;
    }

    if (!check("entropy binary encoding", test_binary_encoding_v3(wallet_entropy)))
        return 1;

    if (!check("entropy JSON encoding", test_json_encoding_v3(wallet_entropy)))
        return 1;

    if (!check("secret_key binary encoding", test_binary_encoding_v3(secret_key)))
        return 1;

    if (!check("secret_key JSON encoding", test_json_encoding_v3(secret_key)))
        return 1;

    // test subwallet-1
    {
        const auto [pub, subwallet] = seed.generate_child_key(44, 0, 0, 0, 1).keys();

        std::cout << "    subwallet(1):  " << subwallet << std::endl << std::endl;

        if (!check("subwallet(1) differs from root", subwallet != secret_key))
            return 1;
    }

    // test subwallet-32
    {
        const auto [pub, subwallet] = seed.generate_child_key(44, 0, 0, 0, 32).keys();

        std::cout << "    subwallet(32): " << subwallet << std::endl << std::endl;

        if (!check("subwallet(32) differs from root", subwallet != secret_key))
            return 1;
    }

    const auto [pub2, secret_key2] = seed.generate_child_key(45, 0, 1, 0, 0).keys();

    if (!check("view key differs from spend key", secret_key2 != secret_key))
        return 1;

    const auto public_key2 = secret_key2.point();

    std::cout << "    view secret: " << secret_key2 << std::endl;
    std::cout << "    view public: " << public_key2 << std::endl;

    // save these for later
    public_key_t public_ephemeral;

    scalar_t secret_ephemeral;

    key_image_t key_image, key_image2;

    std::cout << std::endl << "=== Stealth Addresses ===" << std::endl;

    {
        std::cout << "    --- Sender ---" << std::endl;

        const auto derivation = Crypto::generate_key_derivation(public_key2, secret_key);

        std::cout << "    derivation:        " << derivation << std::endl;

        const auto derivation_scalar = Crypto::derivation_to_scalar(derivation, 64);

        std::cout << "    derivation_scalar: " << derivation_scalar << std::endl;

        const auto expected_public_ephemeral = Crypto::derive_public_key(derivation_scalar, public_key2);

        std::cout << "    derive_public_key: " << expected_public_ephemeral << std::endl;

        std::cout << "    --- Receiver ---" << std::endl;

        const auto derivation2 = Crypto::generate_key_derivation(public_key, secret_key2);

        std::cout << "    derivation:        " << derivation2 << std::endl;

        const auto derivation_scalar2 = Crypto::derivation_to_scalar(derivation2, 64);

        std::cout << "    derivation_scalar: " << derivation_scalar2 << std::endl;

        public_ephemeral = Crypto::derive_public_key(derivation_scalar2, public_key2);

        std::cout << "    derive_public_key: " << public_ephemeral << std::endl;

        secret_ephemeral = Crypto::derive_secret_key(derivation_scalar2, secret_key2);

        std::cout << "    derive_secret_key: " << secret_ephemeral << std::endl << std::endl;

        {
            const auto ephemeral_check = secret_ephemeral.point();

            if (!check("public_ephemeral matches", ephemeral_check == expected_public_ephemeral))
                return 1;
        }

        // check underive_public_key
        {
            const auto underived_public_key = Crypto::underive_public_key(derivation, 64, public_ephemeral);

            std::cout << "    underive_public_key: " << underived_public_key << std::endl << std::endl;

            if (!check("underive_public_key", underived_public_key == public_key2))
                return 1;
        }

        key_image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

        if (!check("key_image subgroup", key_image.check_subgroup()))
            return 1;

        std::cout << "    key_image:    " << key_image << std::endl;

        key_image2 = Crypto::generate_key_image_v2(secret_ephemeral);

        if (!check("key_image_v2 subgroup", key_image2.check_subgroup()))
            return 1;

        std::cout << "    key_image_v2: " << key_image2 << std::endl;
    }

    std::cout << std::endl << "=== Audit Proofs ===" << std::endl;

    // Audit Output Proofs
    {
        const auto [public_keys, secret_keys] = Crypto::generate_keys_m(20);

        const auto [success, proof] = Crypto::Audit::generate_outputs_proof(secret_keys);

        if (!check("generate_outputs_proof", success))
            return 1;

        std::cout << std::endl << proof << std::endl << std::endl;

        const auto [valid, key_images] = Crypto::Audit::check_outputs_proof(public_keys, proof);

        if (!check("check_outputs_proof", valid))
            return 1;
    }

    std::cout << std::endl << "=== Signatures ===" << std::endl;

    // Single Signature
    {
        const auto signature = Crypto::Signature::generate_signature(SHA3_HASH, secret_key);

        check("generate_signature", true);

        if (!check("check_signature", Crypto::Signature::check_signature(SHA3_HASH, public_key, signature)))
            return 1;
    }

    // RFC8032 Signature
    {
        const auto signature = Crypto::RFC8032::generate_signature(SHA3_HASH, secret_key);

        check("rfc8032 generate_signature", true);

        if (!check("rfc8032 check_signature", Crypto::RFC8032::check_signature(SHA3_HASH, public_key, signature)))
            return 1;
    }

    std::cout << std::endl << "=== Borromean Ring Signature ===" << std::endl;

    // Borromean
    {
        auto public_keys = point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto [gen_success, signature] =
            Crypto::RingSignature::Borromean::generate_ring_signature(SHA3_HASH, secret_ephemeral, public_keys);

        if (!check("borromean generate_ring_signature", gen_success))
            return 1;

        std::cout << signature << std::endl;
        std::cout << "    " << signature.to_string() << std::endl << std::endl;

        if (!check(
                "borromean check_ring_signature",
                Crypto::RingSignature::Borromean::check_ring_signature(SHA3_HASH, key_image, public_keys, signature)))
            return 1;

        if (!check("borromean binary encoding", test_binary_encoding_v2(signature)))
            return 1;

        if (!check("borromean JSON encoding", test_json_encoding(signature)))
            return 1;
    }

    std::cout << std::endl << "=== CLSAG Ring Signature ===" << std::endl;

    // CLSAG
    {
        auto public_keys = point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto [gen_sucess, signature] =
            Crypto::RingSignature::CLSAG::generate_ring_signature(SHA3_HASH, secret_ephemeral, public_keys);

        if (!check("clsag generate_ring_signature", gen_sucess))
            return 1;

        std::cout << signature << std::endl;
        std::cout << "    " << signature.to_string() << std::endl << std::endl;

        if (!check(
                "clsag check_ring_signature",
                Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, key_image, public_keys, signature)))
            return 1;

        if (!check("clsag binary encoding", test_binary_encoding(signature)))
            return 1;

        if (!check("clsag JSON encoding", test_json_encoding(signature)))
            return 1;
    }

    std::cout << std::endl << "=== CLSAG Ring Signature w/ Commitments ===" << std::endl;

    // CLSAG w/ Commitments
    {
        auto public_keys = point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto input_blinding = scalar_t::random();

        const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

        std::vector<pedersen_commitment_t> public_commitments = point_t::random(RING_SIZE);

        public_commitments[RING_SIZE / 2] = input_commitment;

        const auto [ps_blindings, ps_commitments] =
            Crypto::RingCT::generate_pseudo_commitments({100}, scalar_t::random(1));

        const auto [gen_sucess, signature] = Crypto::RingSignature::CLSAG::generate_ring_signature(
            SHA3_HASH,
            secret_ephemeral,
            public_keys,
            input_blinding,
            public_commitments,
            ps_blindings[0],
            ps_commitments[0]);

        if (!check("clsag+commit generate_ring_signature", gen_sucess))
            return 1;

        std::cout << signature << std::endl;
        std::cout << "    " << signature.to_string() << std::endl << std::endl;

        if (!check(
                "clsag+commit check_ring_signature",
                Crypto::RingSignature::CLSAG::check_ring_signature(
                    SHA3_HASH, key_image, public_keys, signature, public_commitments)))
            return 1;

        if (!check("clsag+commit binary encoding", test_binary_encoding(signature)))
            return 1;

        if (!check("clsag+commit JSON encoding", test_json_encoding(signature)))
            return 1;
    }

    std::cout << std::endl << "=== MLSAG Ring Signature ===" << std::endl;

    // MLSAG
    {
        auto public_keys = point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto [gen_sucess, signature] =
            Crypto::RingSignature::MLSAG::generate_ring_signature(SHA3_HASH, secret_ephemeral, public_keys);

        if (!check("mlsag generate_ring_signature", gen_sucess))
            return 1;

        std::cout << signature << std::endl;
        std::cout << "    " << signature.to_string() << std::endl << std::endl;

        if (!check(
                "mlsag check_ring_signature",
                Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, key_image, public_keys, signature)))
            return 1;

        if (!check("mlsag binary encoding", test_binary_encoding(signature)))
            return 1;

        if (!check("mlsag JSON encoding", test_json_encoding(signature)))
            return 1;
    }

    std::cout << std::endl << "=== MLSAG Ring Signature w/ Commitments ===" << std::endl;

    // MLSAG w/ Commitments
    {
        auto public_keys = point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto input_blinding = scalar_t::random();

        const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

        std::vector<pedersen_commitment_t> public_commitments = point_t::random(RING_SIZE);

        public_commitments[RING_SIZE / 2] = input_commitment;

        const auto [ps_blindings, ps_commitments] =
            Crypto::RingCT::generate_pseudo_commitments({100}, scalar_t::random(1));

        const auto [gen_sucess, signature] = Crypto::RingSignature::MLSAG::generate_ring_signature(
            SHA3_HASH,
            secret_ephemeral,
            public_keys,
            input_blinding,
            public_commitments,
            ps_blindings[0],
            ps_commitments[0]);

        if (!check("mlsag+commit generate_ring_signature", gen_sucess))
            return 1;

        std::cout << signature << std::endl;
        std::cout << "    " << signature.to_string() << std::endl << std::endl;

        if (!check(
                "mlsag+commit check_ring_signature",
                Crypto::RingSignature::MLSAG::check_ring_signature(
                    SHA3_HASH, key_image, public_keys, signature, public_commitments)))
            return 1;

        if (!check("mlsag+commit binary encoding", test_binary_encoding(signature)))
            return 1;

        if (!check("mlsag+commit JSON encoding", test_json_encoding(signature)))
            return 1;
    }

    std::cout << std::endl << "=== Triptych Ring Signature ===" << std::endl;

    // Triptych
    {
        auto public_keys = point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        const auto input_blinding = scalar_t::random();

        const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

        std::vector<pedersen_commitment_t> public_commitments = point_t::random(RING_SIZE);

        public_commitments[RING_SIZE / 2] = input_commitment;

        const auto [ps_blindings, ps_commitments] =
            Crypto::RingCT::generate_pseudo_commitments({100}, scalar_t::random(1));

        const auto [gen_sucess, signature] = Crypto::RingSignature::Triptych::generate_ring_signature(
            SHA3_HASH,
            secret_ephemeral,
            public_keys,
            input_blinding,
            public_commitments,
            ps_blindings[0],
            ps_commitments[0]);

        if (!check("triptych generate_ring_signature", gen_sucess))
            return 1;

        std::cout << signature << std::endl;
        std::cout << "    " << signature.to_string() << std::endl << std::endl;

        if (!check(
                "triptych check_ring_signature",
                Crypto::RingSignature::Triptych::check_ring_signature(
                    SHA3_HASH, key_image2, public_keys, signature, public_commitments)))
            return 1;

        if (!check("triptych binary encoding", test_binary_encoding(signature)))
            return 1;

        if (!check("triptych JSON encoding", test_json_encoding(signature)))
            return 1;
    }

    std::cout << std::endl << "=== RingCT ===" << std::endl;

    // RingCT Basics
    {
        auto blinding_factors = scalar_t::random(2);

        for (auto &factor : blinding_factors)
        {
            factor = Crypto::RingCT::generate_commitment_blinding_factor(factor);
        }

        const auto C_1 = Crypto::RingCT::generate_pedersen_commitment(blinding_factors[0], 1000);

        const auto C_2 = Crypto::RingCT::generate_pedersen_commitment(blinding_factors[1], 1000);

        const auto C_fee = Crypto::RingCT::generate_pedersen_commitment({0}, 100);

        std::cout << "    pedersen commitments:" << std::endl;
        std::cout << "      C_1:   " << C_1 << std::endl;
        std::cout << "      C_2:   " << C_2 << std::endl;
        std::cout << "      C_fee: " << C_fee << std::endl;

        const auto CT = C_1 + C_2 + C_fee;

        const auto [pseudo_blinding_factors, pseudo_commitments] =
            Crypto::RingCT::generate_pseudo_commitments({2000, 100}, blinding_factors);

        std::cout << "    pseudo commitments:" << std::endl;

        for (const auto &commitment : pseudo_commitments)
            std::cout << "      " << commitment << std::endl;

        std::cout << std::endl;

        const auto PT = point_vector_t(pseudo_commitments).sum();

        if (!check("generate_pseudo_commitments", PT == CT))
            return 1;

        if (!check(
                "check_commitments_parity",
                Crypto::RingCT::check_commitments_parity(pseudo_commitments, {C_1, C_2}, 100)))
            return 1;

        // amount masking (hiding)
        {
            const auto derivation_scalar = scalar_t::random();

            const auto amount_mask = Crypto::RingCT::generate_amount_mask(derivation_scalar);

            const scalar_t amount = scalar_t(13371337);

            const auto masked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, amount);

            const auto unmasked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, masked_amount);

            if (!check(
                    "toggle_masked_amount",
                    masked_amount.to_uint64_t() != amount.to_uint64_t()
                        && unmasked_amount.to_uint64_t() == amount.to_uint64_t()))
                return 1;
        }
    }

    std::cout << std::endl << "=== Bulletproofs ===" << std::endl;

    // Bulletproofs M=1 (base tests: tamper, out-of-range, encoding)
    {
        auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove({1000}, scalar_t::random(1));

        if (!check("bulletproofs M=1 verify valid", Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments})))
            return 1;

        std::cout << proof << std::endl;
        std::cout << "    " << proof.to_string() << std::endl << std::endl;

        proof.taux *= Crypto::TWO;

        if (!check("bulletproofs reject tampered", !Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments})))
            return 1;

        auto [proof2, commitments2] = Crypto::RangeProofs::Bulletproofs::prove({1000}, scalar_t::random(1), 8);

        if (!check(
                "bulletproofs reject out-of-range",
                !Crypto::RangeProofs::Bulletproofs::verify({proof2}, {commitments2}, 8)))
            return 1;

        if (!check("bulletproofs binary encoding", test_binary_encoding(proof)))
            return 1;

        if (!check("bulletproofs JSON encoding", test_json_encoding(proof)))
            return 1;
    }

    // Bulletproofs M=2,4,8,16
    for (const size_t M : {2, 4, 8, 16})
    {
        std::vector<uint64_t> amounts(M);
        for (size_t i = 0; i < M; ++i)
            amounts[i] = 1000 + i * 100;

        auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove(amounts, scalar_t::random(M));

        if (!check(
                ("bulletproofs M=" + std::to_string(M) + " verify valid").c_str(),
                Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments})))
            return 1;

        std::cout << std::endl << "  --- M=" << M << " ---" << std::endl;
        std::cout << proof << std::endl;
        std::cout << "    " << proof.to_string() << std::endl << std::endl;

        if (!check(("bulletproofs M=" + std::to_string(M) + " binary encoding").c_str(), test_binary_encoding(proof)))
            return 1;
    }

    // Bulletproofs batch verify with mixed M values
    {
        auto [proof1, c1] = Crypto::RangeProofs::Bulletproofs::prove({500}, scalar_t::random(1));
        auto [proof2, c2] = Crypto::RangeProofs::Bulletproofs::prove({600, 700}, scalar_t::random(2));

        if (!check(
                "bulletproofs mixed batch verify",
                Crypto::RangeProofs::Bulletproofs::verify({proof1, proof2}, {c1, c2})))
            return 1;
    }

    std::cout << std::endl << "=== Bulletproofs+ ===" << std::endl;

    // Bulletproofs+ M=1 (base tests: tamper, out-of-range, encoding)
    {
        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, scalar_t::random(1));

        if (!check(
                "bulletproofs+ M=1 verify valid",
                Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments})))
            return 1;

        std::cout << proof << std::endl;
        std::cout << "    " << proof.to_string() << std::endl << std::endl;

        proof.d1 *= Crypto::TWO;

        if (!check(
                "bulletproofs+ reject tampered",
                !Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments})))
            return 1;

        auto [proof2, commitments2] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, scalar_t::random(1), 8);

        if (!check(
                "bulletproofs+ reject out-of-range",
                !Crypto::RangeProofs::BulletproofsPlus::verify({proof2}, {commitments2}, 8)))
            return 1;

        if (!check("bulletproofs+ binary encoding", test_binary_encoding(proof)))
            return 1;

        if (!check("bulletproofs+ JSON encoding", test_json_encoding(proof)))
            return 1;
    }

    // Bulletproofs+ M=2,4,8,16
    for (const size_t M : {2, 4, 8, 16})
    {
        std::vector<uint64_t> amounts(M);
        for (size_t i = 0; i < M; ++i)
            amounts[i] = 1000 + i * 100;

        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove(amounts, scalar_t::random(M));

        if (!check(
                ("bulletproofs+ M=" + std::to_string(M) + " verify valid").c_str(),
                Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments})))
            return 1;

        std::cout << std::endl << "  --- M=" << M << " ---" << std::endl;
        std::cout << proof << std::endl;
        std::cout << "    " << proof.to_string() << std::endl << std::endl;

        if (!check(("bulletproofs+ M=" + std::to_string(M) + " binary encoding").c_str(), test_binary_encoding(proof)))
            return 1;
    }

    // Bulletproofs+ batch verify with mixed M values
    {
        auto [proof1, c1] = Crypto::RangeProofs::BulletproofsPlus::prove({500}, scalar_t::random(1));
        auto [proof2, c2] = Crypto::RangeProofs::BulletproofsPlus::prove({600, 700}, scalar_t::random(2));

        if (!check(
                "bulletproofs+ mixed batch verify",
                Crypto::RangeProofs::BulletproofsPlus::verify({proof1, proof2}, {c1, c2})))
            return 1;
    }

    std::cout << std::endl << "=== Bulletproofs++ ===" << std::endl;

    // Bulletproofs++ M=1 (base tests: tamper, out-of-range, encoding)
    {
        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPP::prove({1000}, scalar_t::random(1));

        if (!check(
                "bulletproofs++ M=1 verify valid", Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments})))
            return 1;

        std::cout << proof << std::endl;
        std::cout << "    " << proof.to_string() << std::endl << std::endl;

        auto tampered = proof;
        tampered.C_l = tampered.C_l + tampered.C_l;

        if (!check(
                "bulletproofs++ reject tampered",
                !Crypto::RangeProofs::BulletproofsPP::verify({tampered}, {commitments})))
            return 1;

        {
            bool threw = false;
            try
            {
                Crypto::RangeProofs::BulletproofsPP::prove({1000}, scalar_t::random(1), 8);
            }
            catch (const std::range_error &)
            {
                threw = true;
            }
            if (!check("bulletproofs++ reject out-of-range", threw))
                return 1;
        }

        if (!check("bulletproofs++ binary encoding", test_binary_encoding(proof)))
            return 1;

        if (!check("bulletproofs++ JSON encoding", test_json_encoding(proof)))
            return 1;
    }

    // Bulletproofs++ M=2,4,8,16
    for (const size_t M : {2, 4, 8, 16})
    {
        std::vector<uint64_t> amounts(M);
        for (size_t i = 0; i < M; ++i)
            amounts[i] = 1000 + i * 100;

        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPP::prove(amounts, scalar_t::random(M));

        if (!check(
                ("bulletproofs++ M=" + std::to_string(M) + " verify valid").c_str(),
                Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments})))
            return 1;

        std::cout << std::endl << "  --- M=" << M << " ---" << std::endl;
        std::cout << proof << std::endl;
        std::cout << "    " << proof.to_string() << std::endl << std::endl;

        if (!check(("bulletproofs++ M=" + std::to_string(M) + " binary encoding").c_str(), test_binary_encoding(proof)))
            return 1;
    }

    // Bulletproofs++ M=3 (tests pow2 padding to M_pad=4)
    {
        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPP::prove({100, 200, 300}, scalar_t::random(3));

        if (!check(
                "bulletproofs++ M=3 verify valid", Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments})))
            return 1;
    }

    // Bulletproofs++ batch verify with mixed M values
    {
        auto [proof1, c1] = Crypto::RangeProofs::BulletproofsPP::prove({500}, scalar_t::random(1));
        auto [proof2, c2] = Crypto::RangeProofs::BulletproofsPP::prove({600, 700}, scalar_t::random(2));

        if (!check(
                "bulletproofs++ mixed batch verify",
                Crypto::RangeProofs::BulletproofsPP::verify({proof1, proof2}, {c1, c2})))
            return 1;
    }

    std::cout << std::endl << "=== DLEQ Proofs ===" << std::endl;

    // DLEQ basic generate/verify
    {
        const auto secret = scalar_t::random();
        const auto G_point = Crypto::G;
        const auto H_point = hash_t::sha3(G_point).point();
        const auto A = secret * G_point;
        const auto B = secret * H_point;

        const auto proof = Crypto::DLEQ::generate_proof(secret, G_point, H_point);

        if (!check("dleq generate_proof", true))
            return 1;

        if (!check("dleq check_proof", Crypto::DLEQ::check_proof(A, B, G_point, H_point, proof)))
            return 1;

        std::cout << proof << std::endl;

        // Wrong secret should fail
        {
            const auto bad_secret = scalar_t::random();
            const auto bad_A = bad_secret * G_point;
            const auto bad_B = bad_secret * H_point;

            if (!check("dleq reject wrong points", !Crypto::DLEQ::check_proof(bad_A, bad_B, G_point, H_point, proof)))
                return 1;
        }

        // Tampered proof should fail
        {
            auto tampered = proof;
            tampered.s = tampered.s + Crypto::ONE;

            if (!check("dleq reject tampered", !Crypto::DLEQ::check_proof(A, B, G_point, H_point, tampered)))
                return 1;
        }

        if (!check("dleq binary encoding", test_binary_encoding(proof)))
            return 1;

        if (!check("dleq JSON encoding", test_json_encoding(proof)))
            return 1;
    }

    std::cout << std::endl << "=== Adapter Signatures ===" << std::endl;

    // Adapter Signature full flow
    {
        const auto [signer_pub, signer_sec] = Crypto::generate_keys();
        const auto witness_y = scalar_t::random();
        const auto statement_Y = witness_y * Crypto::G;

        const auto pre_sig = Crypto::AdapterSignature::pre_sign(SHA3_HASH, signer_sec, statement_Y);

        if (!check("adapter pre_sign", true))
            return 1;

        if (!check(
                "adapter check_pre_signature",
                Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, statement_Y, pre_sig)))
            return 1;

        std::cout << pre_sig << std::endl;

        const auto adapted_sig = Crypto::AdapterSignature::adapt(pre_sig, witness_y);

        if (!check("adapter adapt", true))
            return 1;

        // Extract witness
        const auto extracted_y = Crypto::AdapterSignature::extract(pre_sig, adapted_sig, statement_Y);

        const auto extracted_Y = extracted_y * Crypto::G;

        if (!check("adapter extract witness", extracted_Y == statement_Y))
            return 1;

        // Tampered pre-signature should fail
        {
            auto tampered = pre_sig;
            tampered.s_prime = tampered.s_prime + Crypto::ONE;

            if (!check(
                    "adapter reject tampered pre_sig",
                    !Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, statement_Y, tampered)))
                return 1;
        }

        if (!check("adapter binary encoding", test_binary_encoding(pre_sig)))
            return 1;

        if (!check("adapter JSON encoding", test_json_encoding(pre_sig)))
            return 1;
    }

    std::cout << std::endl << "=== VRF (Native) ===" << std::endl;

    // VRF native prove/verify
    {
        const auto [vrf_pub, vrf_sec] = Crypto::generate_keys();
        const std::vector<unsigned char> alpha = {0x01, 0x02, 0x03, 0x04};

        const auto [proof, beta] = Crypto::VRF::prove(vrf_sec, alpha);

        if (!check("vrf prove", true))
            return 1;

        std::cout << proof << std::endl;
        std::cout << "    beta: " << beta << std::endl << std::endl;

        const auto [valid, beta2] = Crypto::VRF::verify(vrf_pub, alpha, proof);

        if (!check("vrf verify", valid))
            return 1;

        if (!check("vrf output matches", beta == beta2))
            return 1;

        // Determinism: same (key, input) -> same output
        {
            const auto [proof2, beta3] = Crypto::VRF::prove(vrf_sec, alpha);
            const auto [valid2, beta4] = Crypto::VRF::verify(vrf_pub, alpha, proof2);

            if (!check("vrf deterministic output", beta3 == beta))
                return 1;
            if (!check("vrf deterministic verify", valid2))
                return 1;
        }

        // Different input -> different output
        {
            const std::vector<unsigned char> alpha2 = {0x05, 0x06, 0x07, 0x08};
            const auto [proof3, beta5] = Crypto::VRF::prove(vrf_sec, alpha2);

            if (!check("vrf different input different output", !(beta5 == beta)))
                return 1;
        }

        // Tampered proof should fail
        {
            auto tampered = proof;
            tampered.s = tampered.s + Crypto::ONE;
            const auto [bad_valid, bad_beta] = Crypto::VRF::verify(vrf_pub, alpha, tampered);

            if (!check("vrf reject tampered", !bad_valid))
                return 1;
        }

        if (!check("vrf binary encoding", test_binary_encoding(proof)))
            return 1;

        if (!check("vrf JSON encoding", test_json_encoding(proof)))
            return 1;
    }

    std::cout << std::endl << "=== VRF (RFC 9381) ===" << std::endl;
    {
        const auto sk = scalar_t::random();
        const auto pk = sk * Crypto::G;
        const std::vector<unsigned char> alpha = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"

        const auto [proof, beta] = Crypto::VRF::RFC9381::prove(sk, alpha);

        if (!check("vrf-rfc9381 prove", !beta.empty()))
            return 1;

        std::cout << proof;
        std::cout << "    beta: " << beta << std::endl;

        const auto [valid, beta2] = Crypto::VRF::RFC9381::verify(pk, alpha, proof);

        if (!check("vrf-rfc9381 verify", valid))
            return 1;

        if (!check("vrf-rfc9381 output matches", beta == beta2))
            return 1;

        // Determinism: same key + input -> same output
        const auto [proof2, beta3] = Crypto::VRF::RFC9381::prove(sk, alpha);

        if (!check("vrf-rfc9381 deterministic output", beta == beta3))
            return 1;

        // Different input -> different output
        const std::vector<unsigned char> alpha2 = {0x57, 0x6f, 0x72, 0x6c, 0x64}; // "World"
        const auto [proof3, beta4] = Crypto::VRF::RFC9381::prove(sk, alpha2);

        if (!check("vrf-rfc9381 different input different output", !(beta == beta4)))
            return 1;

        // Tampered proof fails
        auto bad_proof = proof;
        bad_proof.s = scalar_t::random();
        const auto [bad_valid, _] = Crypto::VRF::RFC9381::verify(pk, alpha, bad_proof);

        if (!check("vrf-rfc9381 reject tampered", !bad_valid))
            return 1;

        if (!check("vrf-rfc9381 binary encoding", test_binary_encoding(proof)))
            return 1;

        if (!check("vrf-rfc9381 JSON encoding", test_json_encoding(proof)))
            return 1;
    }

    std::cout << std::endl << "==================" << std::endl;
    std::cout << "Total:  " << tests_run << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
