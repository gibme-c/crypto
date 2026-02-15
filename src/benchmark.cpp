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

// scale down warmup for expensive benchmarks (default 10k is too many for ms-range operations)
#define BENCHMARK_WARMUP_ITERATIONS 100

#include <benchmark.h>
#include <cstring>
#include <crypto.h>

#define RING_SIZE 4

static bool has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], flag) == 0)
        {
            return true;
        }
    }

    return false;
}

const crypto_hash_t INPUT_DATA = {0xcf, 0xc7, 0x65, 0xd9, 0x05, 0xc6, 0x5e, 0x2b, 0x61, 0x81, 0x6d,
                                  0xc1, 0xf0, 0xfd, 0x69, 0xf6, 0xf6, 0x77, 0x9f, 0x36, 0xed, 0x62,
                                  0x39, 0xac, 0x7e, 0x21, 0xff, 0x51, 0xef, 0x2c, 0x89, 0x1e};

const crypto_hash_t SHA3_HASH = {0x97, 0x45, 0x06, 0x60, 0x1a, 0x60, 0xdc, 0x46, 0x5e, 0x6e, 0x9a,
                                 0xcd, 0xdb, 0x56, 0x38, 0x89, 0xe6, 0x34, 0x71, 0x84, 0x9e, 0xc4,
                                 0x19, 0x86, 0x56, 0x55, 0x03, 0x54, 0xb8, 0x54, 0x1f, 0xcb};

int main(int argc, char **argv)
{
    const bool advanced_only = has_flag(argc, argv, "--advanced-only");

    if (has_flag(argc, argv, "--autotune"))
    {
        std::cout << "Running ed25519 autotune..." << std::flush;
        ed25519_autotune();
        std::cout << " done." << std::endl;
    }

    std::cout << std::endl << std::endl << std::endl;

    benchmark_header();

    const auto _keys = Crypto::generate_keys();
    const auto &point = std::get<0>(_keys);
    const auto &scalar = std::get<1>(_keys);

    const auto ds = Crypto::derivation_to_scalar(point, 64);

    const auto _eph_keys = Crypto::generate_keys();
    const auto &public_ephemeral = std::get<0>(_eph_keys);
    const auto &secret_ephemeral = std::get<1>(_eph_keys);

    auto key_image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

    if (!advanced_only)
    {
        benchmark(
            []() { crypto_hash_t::sha3(INPUT_DATA); }, "hash_t::sha3", BENCHMARK_PERFORMANCE_ITERATIONS_LONG);

        benchmark(
            []() { crypto_hash_t::blake2b(INPUT_DATA); },
            "hash_t::blake2b",
            BENCHMARK_PERFORMANCE_ITERATIONS_LONG);

        benchmark([]() { crypto_hash_t::argon2d(INPUT_DATA, 4, 256, 1); }, "hash_t::argon2d", 100);

        benchmark([]() { crypto_hash_t::argon2i(INPUT_DATA, 4, 256, 1); }, "hash_t::argon2i", 100);

        benchmark([]() { crypto_hash_t::argon2id(INPUT_DATA, 4, 256, 1); }, "hash_t::argon2id", 100);

        std::cout << std::endl;

        benchmark([]() { crypto_entropy_t::random(); }, "entropy_t::random");

        benchmark([]() { const auto hash = crypto_hash_t::random(); }, "hash_t::random");

        benchmark([]() { const auto [point, scalar] = Crypto::generate_keys(); }, "generate_keys");

        benchmark(
            [&point]() { const auto base58 = Crypto::Base58::encode(point.serialize()); },
            "Base58::encode");

        const auto encoded = Crypto::Base58::encode(point.serialize());

        benchmark(
            [&encoded]() { const auto [succes, reader] = Crypto::Base58::decode(encoded); },
            "Base58::decode");

        std::cout << std::endl;

        benchmark(
            [&point, &scalar]() { Crypto::generate_key_derivation(point, scalar); },
            "generate_key_derivation");

        benchmark([&ds, &point]() { Crypto::derive_public_key(ds, point); }, "derive_public_key");

        benchmark([&ds, &scalar]() { Crypto::derive_secret_key(ds, scalar); }, "derive_secret_key");

        benchmark([&point]() { Crypto::underive_public_key(point, 64, point); }, "underive_public_key");

        benchmark(
            [&point, &scalar]() { Crypto::generate_key_image(point, scalar); },
            "generate_key_image");

        benchmark(
            [&key_image]() { const auto valid = key_image.check_subgroup(); }, "point_t::check_subgroup");
    }

    // signing
    {
        crypto_signature_t sig;

        std::cout << std::endl;

        benchmark(
            [&sig, &scalar]() { sig = Crypto::Signature::generate_signature(SHA3_HASH, scalar); },
            "Signature::generate");

        benchmark(
            [&sig, &point]() { Crypto::Signature::check_signature(SHA3_HASH, point, sig); },
            "Signature::check");
    }

    // signing RF8032
    {
        crypto_signature_t sig;

        std::cout << std::endl;

        benchmark(
            [&sig, &scalar]() { sig = Crypto::RFC8032::generate_signature(SHA3_HASH, scalar); },
            "RFC8032::generate");

        benchmark(
            [&sig, &point]() { Crypto::RFC8032::check_signature(SHA3_HASH, point, sig); },
            "RFC8032::check");
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
                    SHA3_HASH, secret_ephemeral, public_keys, RING_SIZE / 2);
                signature = sigs;
            },
            "Borromean::sign",
            100);

        benchmark(
            [&public_keys, &image, &signature]()
            { Crypto::RingSignature::Borromean::check_ring_signature(SHA3_HASH, image, public_keys, signature); },
            "Borromean::verify",
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
                const auto [success, sig] = Crypto::RingSignature::CLSAG::generate_ring_signature(
                    SHA3_HASH, secret_ephemeral, public_keys, RING_SIZE / 2);
                signature = sig;
            },
            "CLSAG::sign",
            100);

        benchmark(
            [&public_keys, &image, &signature]()
            { Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, image, public_keys, signature); },
            "CLSAG::verify",
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

        const auto _ps_result1 =
            Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));
        const auto &ps_blindings = std::get<0>(_ps_result1);
        const auto &ps_commitments = std::get<1>(_ps_result1);

        std::cout << std::endl;

        benchmark(
            [&public_keys,
             &secret_ephemeral,
             &signature,
             &input_blinding,
             &public_commitments,
             &ps_blindings,
             &ps_commitments]()
            {
                const auto [success, sig] = Crypto::RingSignature::CLSAG::generate_ring_signature(
                    SHA3_HASH,
                    secret_ephemeral,
                    public_keys,
                    RING_SIZE / 2,
                    input_blinding,
                    public_commitments,
                    ps_blindings[0],
                    ps_commitments[0]);
                signature = sig;
            },
            "CLSAG::sign [w/ commitments]",
            100);

        benchmark(
            [&public_keys, &image, &signature, &public_commitments]() {
                Crypto::RingSignature::CLSAG::check_ring_signature(
                    SHA3_HASH, image, public_keys, signature, public_commitments);
            },
            "CLSAG::verify [w/ commitments]",
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

        const auto _ps_result2 =
            Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));
        const auto &ps_blindings = std::get<0>(_ps_result2);
        const auto &ps_commitments = std::get<1>(_ps_result2);

        std::cout << std::endl;

        benchmark(
            [&public_keys,
             &secret_ephemeral,
             &signature,
             &input_blinding,
             &public_commitments,
             &ps_blindings,
             &ps_commitments]()
            {
                const auto [success, sig] = Crypto::RingSignature::Triptych::generate_ring_signature(
                    SHA3_HASH,
                    secret_ephemeral,
                    public_keys,
                    RING_SIZE / 2,
                    input_blinding,
                    public_commitments,
                    ps_blindings[0],
                    ps_commitments[0]);
                signature = sig;
            },
            "Triptych::sign",
            100);

        benchmark(
            [&public_keys, &image, &signature, &public_commitments]()
            {
                Crypto::RingSignature::Triptych::check_ring_signature(
                    SHA3_HASH, image, public_keys, signature, public_commitments);
            },
            "Triptych::verify",
            100);
    }

    // RingCT
    {
        const auto blinding_factor = crypto_scalar_t::random();

        std::cout << std::endl;

        benchmark(
            [&blinding_factor]() { Crypto::RingCT::generate_pedersen_commitment(blinding_factor, 10000); },
            "RingCT::pedersen_commitment");

        benchmark(
            [&blinding_factor]() { Crypto::RingCT::generate_pseudo_commitments({10000}, {blinding_factor}); },
            "RingCT::pseudo_commitments");
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
            "Bulletproofs::prove",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}); },
            "Bulletproofs::verify",
            10);

        benchmark(
            [&proof, &commitments]() {
                Crypto::RangeProofs::Bulletproofs::verify({proof, proof}, {commitments, commitments});
            },
            "Bulletproofs::verify [batched]",
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
            "Bulletproofs+::prove",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}); },
            "Bulletproofs+::verify",
            10);

        benchmark(
            [&proof, &commitments]() {
                Crypto::RangeProofs::BulletproofsPlus::verify({proof, proof}, {commitments, commitments});
            },
            "Bulletproofs+::verify [batched]",
            10);
    }

    // Bulletproofs++ benchmarks
    {
        const auto blinding_factors = crypto_scalar_t::random(1);

        // seed the memory cache as to not taint the benchmark
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove({1000}, blinding_factors);

        crypto_bulletproof_pp_t proof;

        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &blinding_factors, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove({1000}, blinding_factors);
                proof = p;
                commitments = c;
            },
            "Bulletproofs++::prove",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments}); },
            "Bulletproofs++::verify",
            10);

        benchmark(
            [&proof, &commitments]() {
                Crypto::RangeProofs::BulletproofsPP::verify({proof, proof}, {commitments, commitments});
            },
            "Bulletproofs++::verify [batched]",
            10);
    }

    std::cout << std::endl << std::endl;

    if (!advanced_only)
    {
        // Complex Benchmark
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

    return 0;
}
