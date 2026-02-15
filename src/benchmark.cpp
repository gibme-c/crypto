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

// scale down warmup for expensive benchmarks (default 10k is too many for ms-range operations)
#define BENCHMARK_WARMUP_ITERATIONS 100

#include <benchmark.h>
#include <crypto.h>
#include <cstring>

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
        benchmark([]() { crypto_hash_t::sha3(INPUT_DATA); }, "hash_t::sha3", BENCHMARK_PERFORMANCE_ITERATIONS_LONG);

        benchmark(
            []() { crypto_hash_t::blake2b(INPUT_DATA); }, "hash_t::blake2b", BENCHMARK_PERFORMANCE_ITERATIONS_LONG);

        benchmark([]() { crypto_hash_t::argon2d(INPUT_DATA, 4, 256, 1); }, "hash_t::argon2d", 100);

        benchmark([]() { crypto_hash_t::argon2i(INPUT_DATA, 4, 256, 1); }, "hash_t::argon2i", 100);

        benchmark([]() { crypto_hash_t::argon2id(INPUT_DATA, 4, 256, 1); }, "hash_t::argon2id", 100);

        std::cout << std::endl;

        benchmark([]() { crypto_entropy_t::random(); }, "entropy_t::random");

        benchmark([]() { const auto hash = crypto_hash_t::random(); }, "hash_t::random");

        benchmark([]() { const auto [point, scalar] = Crypto::generate_keys(); }, "generate_keys");

        benchmark([&point]() { const auto base58 = Crypto::Base58::encode(point.serialize()); }, "Base58::encode");

        const auto encoded = Crypto::Base58::encode(point.serialize());

        benchmark([&encoded]() { const auto [succes, reader] = Crypto::Base58::decode(encoded); }, "Base58::decode");

        std::cout << std::endl;

        benchmark([&point, &scalar]() { Crypto::generate_key_derivation(point, scalar); }, "generate_key_derivation");

        benchmark([&ds, &point]() { Crypto::derive_public_key(ds, point); }, "derive_public_key");

        benchmark([&ds, &scalar]() { Crypto::derive_secret_key(ds, scalar); }, "derive_secret_key");

        benchmark([&point]() { Crypto::underive_public_key(point, 64, point); }, "underive_public_key");

        benchmark([&point, &scalar]() { Crypto::generate_key_image(point, scalar); }, "generate_key_image");

        benchmark([&key_image]() { const auto valid = key_image.check_subgroup(); }, "point_t::check_subgroup");
    }

    // signing
    {
        crypto_signature_t sig;

        std::cout << std::endl;

        benchmark(
            [&sig, &scalar]() { sig = Crypto::Signature::generate_signature(SHA3_HASH, scalar); },
            "Signature::generate");

        benchmark([&sig, &point]() { Crypto::Signature::check_signature(SHA3_HASH, point, sig); }, "Signature::check");
    }

    // signing RF8032
    {
        crypto_signature_t sig;

        std::cout << std::endl;

        benchmark(
            [&sig, &scalar]() { sig = Crypto::RFC8032::generate_signature(SHA3_HASH, scalar); }, "RFC8032::generate");

        benchmark([&sig, &point]() { Crypto::RFC8032::check_signature(SHA3_HASH, point, sig); }, "RFC8032::check");
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

        const auto _ps_result1 = Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));
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

    // MLSAG
    {
        auto public_keys = crypto_point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        crypto_mlsag_signature_t signature;

        const auto image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

        std::cout << std::endl;

        benchmark(
            [&public_keys, &secret_ephemeral, &signature]()
            {
                const auto [success, sig] = Crypto::RingSignature::MLSAG::generate_ring_signature(
                    SHA3_HASH, secret_ephemeral, public_keys, RING_SIZE / 2);
                signature = sig;
            },
            "MLSAG::sign",
            100);

        benchmark(
            [&public_keys, &image, &signature]()
            { Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, image, public_keys, signature); },
            "MLSAG::verify",
            100);
    }

    // MLSAG w/ Commitments
    {
        auto public_keys = crypto_point_t::random(RING_SIZE);

        public_keys[RING_SIZE / 2] = public_ephemeral;

        crypto_mlsag_signature_t signature;

        const auto image = Crypto::generate_key_image(public_ephemeral, secret_ephemeral);

        const auto input_blinding = crypto_scalar_t::random();

        const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

        std::vector<crypto_pedersen_commitment_t> public_commitments = crypto_point_t::random(RING_SIZE);

        public_commitments[RING_SIZE / 2] = input_commitment;

        const auto _ps_result2 = Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));
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
                const auto [success, sig] = Crypto::RingSignature::MLSAG::generate_ring_signature(
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
            "MLSAG::sign [w/ commitments]",
            100);

        benchmark(
            [&public_keys, &image, &signature, &public_commitments]() {
                Crypto::RingSignature::MLSAG::check_ring_signature(
                    SHA3_HASH, image, public_keys, signature, public_commitments);
            },
            "MLSAG::verify [w/ commitments]",
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

        const auto _ps_result2 = Crypto::RingCT::generate_pseudo_commitments({100}, crypto_scalar_t::random(1));
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

    // Bulletproofs M=2
    {
        const auto bf2 = crypto_scalar_t::random(2);
        const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove({1000, 2000}, bf2);

        crypto_bulletproof_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf2, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove({1000, 2000}, bf2);
                proof = p;
                commitments = c;
            },
            "Bulletproofs::prove [M=2]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}); },
            "Bulletproofs::verify [M=2]",
            10);
    }

    // Bulletproofs M=4
    {
        const auto bf4 = crypto_scalar_t::random(4);
        const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove({10, 20, 30, 40}, bf4);

        crypto_bulletproof_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf4, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove({10, 20, 30, 40}, bf4);
                proof = p;
                commitments = c;
            },
            "Bulletproofs::prove [M=4]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}); },
            "Bulletproofs::verify [M=4]",
            10);
    }

    // Bulletproofs M=8
    {
        const auto bf = crypto_scalar_t::random(8);
        const std::vector<uint64_t> amounts = {10, 20, 30, 40, 50, 60, 70, 80};
        const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove(amounts, bf);

        crypto_bulletproof_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf, &amounts, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove(amounts, bf);
                proof = p;
                commitments = c;
            },
            "Bulletproofs::prove [M=8]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}); },
            "Bulletproofs::verify [M=8]",
            10);
    }

    // Bulletproofs M=16
    {
        const auto bf = crypto_scalar_t::random(16);
        const std::vector<uint64_t> amounts = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160};
        const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove(amounts, bf);

        crypto_bulletproof_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf, &amounts, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::Bulletproofs::prove(amounts, bf);
                proof = p;
                commitments = c;
            },
            "Bulletproofs::prove [M=16]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}); },
            "Bulletproofs::verify [M=16]",
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

    // Bulletproofs+ M=2
    {
        const auto bf2 = crypto_scalar_t::random(2);
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove({1000, 2000}, bf2);

        crypto_bulletproof_plus_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf2, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove({1000, 2000}, bf2);
                proof = p;
                commitments = c;
            },
            "Bulletproofs+::prove [M=2]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}); },
            "Bulletproofs+::verify [M=2]",
            10);
    }

    // Bulletproofs+ M=4
    {
        const auto bf4 = crypto_scalar_t::random(4);
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove({10, 20, 30, 40}, bf4);

        crypto_bulletproof_plus_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf4, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove({10, 20, 30, 40}, bf4);
                proof = p;
                commitments = c;
            },
            "Bulletproofs+::prove [M=4]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}); },
            "Bulletproofs+::verify [M=4]",
            10);
    }

    // Bulletproofs+ M=8
    {
        const auto bf = crypto_scalar_t::random(8);
        const std::vector<uint64_t> amounts = {10, 20, 30, 40, 50, 60, 70, 80};
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove(amounts, bf);

        crypto_bulletproof_plus_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf, &amounts, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove(amounts, bf);
                proof = p;
                commitments = c;
            },
            "Bulletproofs+::prove [M=8]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}); },
            "Bulletproofs+::verify [M=8]",
            10);
    }

    // Bulletproofs+ M=16
    {
        const auto bf = crypto_scalar_t::random(16);
        const std::vector<uint64_t> amounts = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160};
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove(amounts, bf);

        crypto_bulletproof_plus_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf, &amounts, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPlus::prove(amounts, bf);
                proof = p;
                commitments = c;
            },
            "Bulletproofs+::prove [M=16]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}); },
            "Bulletproofs+::verify [M=16]",
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

    // Bulletproofs++ M=2 benchmarks
    {
        const auto bf2 = crypto_scalar_t::random(2);
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove({1000, 2000}, bf2);

        crypto_bulletproof_pp_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf2, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove({1000, 2000}, bf2);
                proof = p;
                commitments = c;
            },
            "Bulletproofs++::prove [M=2]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments}); },
            "Bulletproofs++::verify [M=2]",
            10);
    }

    // Bulletproofs++ M=4 benchmarks
    {
        const auto bf4 = crypto_scalar_t::random(4);
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove({10, 20, 30, 40}, bf4);

        crypto_bulletproof_pp_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf4, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove({10, 20, 30, 40}, bf4);
                proof = p;
                commitments = c;
            },
            "Bulletproofs++::prove [M=4]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments}); },
            "Bulletproofs++::verify [M=4]",
            10);
    }

    // Bulletproofs++ M=8
    {
        const auto bf = crypto_scalar_t::random(8);
        const std::vector<uint64_t> amounts = {10, 20, 30, 40, 50, 60, 70, 80};
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove(amounts, bf);

        crypto_bulletproof_pp_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf, &amounts, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove(amounts, bf);
                proof = p;
                commitments = c;
            },
            "Bulletproofs++::prove [M=8]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments}); },
            "Bulletproofs++::verify [M=8]",
            10);
    }

    // Bulletproofs++ M=16
    {
        const auto bf = crypto_scalar_t::random(16);
        const std::vector<uint64_t> amounts = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160};
        const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove(amounts, bf);

        crypto_bulletproof_pp_t proof;
        std::vector<crypto_pedersen_commitment_t> commitments;

        std::cout << std::endl;

        benchmark(
            [&proof, &bf, &amounts, &commitments]()
            {
                const auto [p, c] = Crypto::RangeProofs::BulletproofsPP::prove(amounts, bf);
                proof = p;
                commitments = c;
            },
            "Bulletproofs++::prove [M=16]",
            10);

        benchmark(
            [&proof, &commitments]() { Crypto::RangeProofs::BulletproofsPP::verify({proof}, {commitments}); },
            "Bulletproofs++::verify [M=16]",
            10);
    }

    // DLEQ
    {
        const auto secret = crypto_scalar_t::random();
        const auto G_point = Crypto::G;
        const auto H_point = crypto_hash_t::sha3(G_point).point();
        const auto A = secret * G_point;
        const auto B = secret * H_point;

        crypto_dleq_proof_t dleq_proof;

        std::cout << std::endl;

        benchmark(
            [&dleq_proof, &secret, &G_point, &H_point]()
            { dleq_proof = Crypto::DLEQ::generate_proof(secret, G_point, H_point); },
            "DLEQ::prove",
            100);

        benchmark(
            [&A, &B, &G_point, &H_point, &dleq_proof]()
            { Crypto::DLEQ::check_proof(A, B, G_point, H_point, dleq_proof); },
            "DLEQ::verify",
            100);
    }

    // Adapter Signatures
    {
        const auto _adapter_keys = Crypto::generate_keys();
        const auto &adapter_pub = std::get<0>(_adapter_keys);
        const auto &adapter_sec = std::get<1>(_adapter_keys);
        const auto witness_y = crypto_scalar_t::random();
        const auto statement_Y = witness_y * Crypto::G;

        crypto_adapter_signature_t adapter_pre_sig;

        std::cout << std::endl;

        benchmark(
            [&adapter_pre_sig, &adapter_sec, &statement_Y]()
            { adapter_pre_sig = Crypto::AdapterSignature::pre_sign(SHA3_HASH, adapter_sec, statement_Y); },
            "Adapter::pre_sign",
            100);

        benchmark(
            [&adapter_pub, &statement_Y, &adapter_pre_sig]()
            { Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, adapter_pub, statement_Y, adapter_pre_sig); },
            "Adapter::verify_pre",
            100);

        benchmark(
            [&adapter_pre_sig, &witness_y]() { Crypto::AdapterSignature::adapt(adapter_pre_sig, witness_y); },
            "Adapter::adapt",
            100);
    }

    // VRF (native)
    {
        const auto _vrf_keys = Crypto::generate_keys();
        const auto &vrf_pub = std::get<0>(_vrf_keys);
        const auto &vrf_sec = std::get<1>(_vrf_keys);
        const std::vector<unsigned char> vrf_alpha = {0x01, 0x02, 0x03, 0x04};

        crypto_vrf_proof_t vrf_proof;
        crypto_hash_t vrf_beta;

        std::cout << std::endl;

        benchmark(
            [&vrf_proof, &vrf_beta, &vrf_sec, &vrf_alpha]()
            {
                const auto [p, b] = Crypto::VRF::prove(vrf_sec, vrf_alpha);
                vrf_proof = p;
                vrf_beta = b;
            },
            "VRF::prove",
            100);

        benchmark(
            [&vrf_pub, &vrf_alpha, &vrf_proof]() { Crypto::VRF::verify(vrf_pub, vrf_alpha, vrf_proof); },
            "VRF::verify",
            100);
    }

    // VRF RFC 9381
    {
        const auto rfc_vrf_sk = crypto_scalar_t::random();
        const auto rfc_vrf_pub = rfc_vrf_sk * Crypto::G;
        const std::vector<unsigned char> rfc_vrf_alpha = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

        benchmark(
            [&rfc_vrf_sk, &rfc_vrf_alpha]() { Crypto::VRF::RFC9381::prove(rfc_vrf_sk, rfc_vrf_alpha); },
            "VRF::RFC9381::prove",
            100);

        const auto _rfc_vrf_result = Crypto::VRF::RFC9381::prove(rfc_vrf_sk, rfc_vrf_alpha);
        const auto &rfc_vrf_proof = std::get<0>(_rfc_vrf_result);

        benchmark(
            [&rfc_vrf_pub, &rfc_vrf_alpha, &rfc_vrf_proof]()
            { Crypto::VRF::RFC9381::verify(rfc_vrf_pub, rfc_vrf_alpha, rfc_vrf_proof); },
            "VRF::RFC9381::verify",
            100);
    }

    // FROST (2-of-3)
    {
        const size_t n = 3, t = 2;

        // Set up DKG once outside the benchmark
        std::vector<std::vector<crypto_frost_secret_share_t>> all_shares(n);
        std::vector<crypto_point_vector_t> all_commitments(n);

        for (size_t i = 0; i < n; ++i)
        {
            auto [shares, commitments] = Crypto::FROST::dkg_part1(i + 1, n, t);
            all_shares[i] = shares;
            all_commitments[i] = commitments;
        }

        std::vector<crypto_frost_key_package_t> key_packages(n);

        for (size_t i = 0; i < n; ++i)
        {
            std::vector<crypto_frost_secret_share_t> received;
            for (size_t sender = 0; sender < n; ++sender)
                received.push_back(all_shares[sender][i]);
            key_packages[i] = Crypto::FROST::dkg_part3(i + 1, received, all_commitments);
        }

        const auto pub_key_package = Crypto::FROST::build_public_key_package(n, all_commitments);

        std::cout << std::endl;

        benchmark(
            [n, t]()
            {
                std::vector<std::vector<crypto_frost_secret_share_t>> sh(n);
                std::vector<crypto_point_vector_t> cm(n);
                for (size_t i = 0; i < n; ++i)
                {
                    auto [s, c] = Crypto::FROST::dkg_part1(i + 1, n, t);
                    sh[i] = s;
                    cm[i] = c;
                }
                for (size_t i = 0; i < n; ++i)
                {
                    std::vector<crypto_frost_secret_share_t> rec;
                    for (size_t j = 0; j < n; ++j)
                        rec.push_back(sh[j][i]);
                    Crypto::FROST::dkg_part3(i + 1, rec, cm);
                }
            },
            "FROST::DKG(2-of-3)",
            10);

        // Signing benchmark (2-of-3 with participants 1,2)
        const std::vector<size_t> signers = {0, 1};

        benchmark(
            [&key_packages, &pub_key_package, &signers]()
            {
                std::vector<crypto_frost_nonce_t> nonces(signers.size());
                std::vector<crypto_frost_nonce_commitment_t> nonce_commitments(signers.size());
                for (size_t i = 0; i < signers.size(); ++i)
                {
                    auto [nonce, commitment] = Crypto::FROST::round1_commit(signers[i] + 1);
                    nonces[i] = nonce;
                    nonce_commitments[i] = commitment;
                }
                std::vector<crypto_frost_signature_share_t> sig_shares(signers.size());
                for (size_t i = 0; i < signers.size(); ++i)
                {
                    sig_shares[i] =
                        Crypto::FROST::round2_sign(SHA3_HASH, key_packages[signers[i]], nonces[i], nonce_commitments);
                }
                Crypto::FROST::aggregate(SHA3_HASH, sig_shares, nonce_commitments, pub_key_package);
            },
            "FROST::sign(2-of-3)",
            100);
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
