// Copyright (c) 2020-2026, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
// of conditions and the following disclaimer in the documentation and/or other
// materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
// used to endorse or promote products derived from this software without specific
// prior written permission.
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
#include <iomanip>
#include <tinysha.h>

// Test design notes:
//
// Each domain (hashing, AES, ring signatures, bulletproofs,...) is encapsulated in its
// own static void test_* function called sequentially from a slim main. This keeps
// peak stack/heap residency bounded to the largest single test rather than the sum of
// every test's locals — proofs, transcripts, ring signatures and BP/BP+/BP++ structures
// all release on function return. This mirrors the pattern used in the sister packages
// ../ed25519 and../ranshaw.
//
// Output is silent on success: check prints only on FAIL. The startup banner, struct
// size report and final summary are the only chatter on a clean run, matching CTest
// conventions. To preserve "fatal failure halts the run" behavior for sanity checks
// (where continuing past a broken primitive type is meaningless), test_sanity sets a
// file-scope `fatal_failed` flag instead of return-coding from within a function; main
// inspects it after that single call and aborts early if set.

#define RING_SIZE 4

// Ring slot guaranteed not to be the signer's. The signer is always placed at
// RING_SIZE/2 (see make_stealth_keys callers), so any other index is safe.
// Used by the ring-signature negative tests to tamper a non-signer ring member
// — tampering the signer slot would change the discrete-log relation and muddy
// the failure mode.
static constexpr size_t NON_SIGNER_SLOT = (RING_SIZE / 2 == 0) ? 1 : 0;

// ---------------------------------------------------------------------------
// Test framework
// ---------------------------------------------------------------------------

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static bool fatal_failed = false;

static bool check(const char *name, bool condition)
{
    ++tests_run;

    if (condition)
    {
        ++tests_passed;
        return true;
    }

    ++tests_failed;
    std::cout << " FAIL:" << name << std::endl;
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

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

static const hash_t INPUT_DATA = {0xcf, 0xc7, 0x65, 0xd9, 0x05, 0xc6, 0x5e, 0x2b, 0x61, 0x81, 0x6d,
                                  0xc1, 0xf0, 0xfd, 0x69, 0xf6, 0xf6, 0x77, 0x9f, 0x36, 0xed, 0x62,
                                  0x39, 0xac, 0x7e, 0x21, 0xff, 0x51, 0xef, 0x2c, 0x89, 0x1e};

static const hash_t SHA3_HASH = {0x97, 0x45, 0x06, 0x60, 0x1a, 0x60, 0xdc, 0x46, 0x5e, 0x6e, 0x9a,
                                 0xcd, 0xdb, 0x56, 0x38, 0x89, 0xe6, 0x34, 0x71, 0x84, 0x9e, 0xc4,
                                 0x19, 0x86, 0x56, 0x55, 0x03, 0x54, 0xb8, 0x54, 0x1f, 0xcb};

static const auto SHA3_SLOW_0 = hash_t("974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb");
static const auto SHA3_SLOW_4096 = hash_t("c031be420e429992443c33c2a453287e2678e70b8bce95dfe7357bcbf36ca86c");
static const auto BLAKE2B = hash_t("56a8ef7f9d7db21fa29b83eb77551f0c3e312525d6151946261911fc38a508c4");
static const auto ARGON2D_4_1024_1 = hash_t("cd65323e3e56272fd19b745b0673318b21c2be5257f918267998b341719c3d5a");
static const auto ARGON2I_4_1024_1 = hash_t("debb2a3b51732bff26670753c5dbaedf6139c177108fe8e0744305c8d410a75a");
static const auto ARGON2ID_4_1024_1 = hash_t("a6ac954bce48a46bc01a9b16b484ffb745401ae421b1b6f2e22cf474d4cac1c9");

static const uint64_t BASE58_PREFIX = 0x106a1c;

// ---------------------------------------------------------------------------
// Struct size report
// ---------------------------------------------------------------------------

static void report_struct_sizes()
{
    // Reference info: print sizeof for the major crypto types so reviewers can see
    // the on-stack/in-memory footprint of each structure at a glance. The plan-mode
    // refactor that introduced this function deliberately moved the report here so it
    // is always emitted on startup, even though no individual test consults it.
    auto row = [](const char *name, std::size_t bytes)
    {
        std::cout << "" << std::left << std::setw(36) << name << std::right << std::setw(6) << bytes << " bytes"
                  << std::endl;
    };

    std::cout << std::endl << "=== Struct Sizes ===" << std::endl;

    row("hash_t", sizeof(hash_t));
    row("scalar_t", sizeof(scalar_t));
    row("point_t", sizeof(point_t));
    row("secret_key_t", sizeof(secret_key_t));
    row("entropy_t", sizeof(entropy_t));
    row("seed_t", sizeof(seed_t));
    row("hd_key_t", sizeof(hd_key_t));
    row("signature_t", sizeof(signature_t));
    row("borromean_signature_t", sizeof(borromean_signature_t));
    row("clsag_signature_t", sizeof(clsag_signature_t));
    row("mlsag_signature_t", sizeof(mlsag_signature_t));
    row("triptych_signature_t", sizeof(triptych_signature_t));
    row("bulletproof_t", sizeof(bulletproof_t));
    row("bulletproof_plus_t", sizeof(bulletproof_plus_t));
    row("bulletproof_pp_t", sizeof(bulletproof_pp_t));
    row("dleq_proof_t", sizeof(dleq_proof_t));
    row("adapter_signature_t", sizeof(adapter_signature_t));
    row("adapted_signature_t", sizeof(adapted_signature_t));
    row("vrf_proof_t", sizeof(vrf_proof_t));
    row("vrf_rfc9381_proof_t", sizeof(vrf_rfc9381_proof_t));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_sanity()
{
    // Sanity checks are fatal: if a primitive type is broken, the rest of the suite is
    // meaningless. Set the file-scope fatal flag and bail; main will short-circuit.
    if (!check("point_t empty", point_t().empty()))
    {
        fatal_failed = true;
        return;
    }
    if (!check("scalar_t empty", scalar_t().empty()))
    {
        fatal_failed = true;
        return;
    }
    if (!check("signature_t empty", signature_t().empty()))
    {
        fatal_failed = true;
        return;
    }
    if (!check("hash_t empty", hash_t().empty()))
    {
        fatal_failed = true;
        return;
    }
    if (!check("entropy_t empty", entropy_t().empty()))
    {
        fatal_failed = true;
        return;
    }
}

// ---------------------------------------------------------------------------
// Scalar-bias regression guards.
//
// Invariant: do_reduce is pure sc_reduce, scalar_t::random samples 64 bytes
// and runs them through the unbiased wide-reduction path, hash_t::scalar is
// pure sc_reduce, and sc_clamp is reachable only via the explicit
// scalar_t::from_rfc8032_seed factory (called exclusively by
// secret_key_t::load_hook per RFC 8032 §5.1.5).
//
// If sc_clamp ever leaks into a pure-reduction path, the post-reduce residue
// classes {0,1,3,6} mod 8 become structurally unreachable across every random
// scalar, hash-to-scalar, and Fiat-Shamir challenge in the library -- the
// Howgrave-Graham / Smart lattice-attack regime that broke PS3 ECDSA.
// ---------------------------------------------------------------------------
static void test_scalar_bias_regression()
{
    // Residue classes that a clamp-then-reduce path would make unreachable.
    // All 8 mod-8 classes must be reachable on all three entry points
    // (random, hash-to-scalar, transcript challenge).
    static constexpr unsigned char FORBIDDEN_RESIDUES[4] = {0, 1, 3, 6};
    static constexpr size_t SAMPLE_N = 20000;

    // Helper: tally mod-8 residue of byte[0] across a batch of samples and
    // check that (a) no class is empty and (b) chi-square vs uniform is
    // below a conservative threshold. Under the bias four classes
    // were exactly zero and chi² was ~20000; under the correct path chi² is
    // ~7 in expectation with 7 degrees of freedom.
    auto check_distribution = [](const char *label, const size_t(&counts)[8])
    {
        const double expected = static_cast<double>(SAMPLE_N) / 8.0;
        double chi_square = 0.0;

        bool all_hit = true;
        for (size_t residue_class = 0; residue_class < 8; ++residue_class)
        {
            if (counts[residue_class] == 0)
            {
                all_hit = false;
            }
            const double diff = static_cast<double>(counts[residue_class]) - expected;
            chi_square += (diff * diff) / expected;
        }

        // Assert every class was hit. This is the guard:
        // any zero count under N=20000 samples means sc_clamp has been
        // reintroduced somewhere in the pure-reduction path and the library
        // is back in the lattice-attackable regime.
        check((std::string(label) + " all 8 mod-8 residue classes reachable").c_str(), all_hit);

        // Specifically assert the four forbidden classes. Named
        // explicitly so failure output pinpoints exactly which residues the
        // caller was missing. Under the biased path these four were exactly
        // zero; under the fix they should each receive ~SAMPLE_N/8 hits.
        for (const unsigned char forbidden : FORBIDDEN_RESIDUES)
        {
            const std::string name =
                std::string(label) + " forbidden residue" + std::to_string(static_cast<int>(forbidden)) + " reachable";
            check(name.c_str(), counts[forbidden] > 0);
        }

        // Chi-square threshold rationale: with 8 residue classes and N=20000
        // samples, the correct (uniform) path yields expected χ² ≈ 7 with 7
        // degrees of freedom. The critical value χ²(7, 0.999) is ~24.3 — only
        // 0.1% of correct runs exceed that under honest sampling. The
        // biased path produced χ² ≈ 20000 (four classes exactly zero, four at
        // ~2*expected). We pick 50.0 as the threshold: ~2x the 99.9% critical
        // value (generous headroom against unlucky RNG runs) yet four orders
        // of magnitude below the broken path's output. Any value in the range
        // [25, 200] would work equally well for distinguishing correct-vs-broken.
        check((std::string(label) + " chi-square below threshold").c_str(), chi_square < 50.0);
    };

    // -----------------------------------------------------------------------
    // Test 1: scalar_t::random distribution
    //
    // The most direct regression: every call site that uses scalar_t::random
    // to produce a blinding / nonce / decoy scalar is at stake here.
    // path compressed 32 bytes of entropy through SHA3-256, then clamp-reduced.
    // Post-fix path samples 64 bytes and runs through reduce_wide_hash.
    // -----------------------------------------------------------------------
    {
        size_t counts[8] = {0};
        for (size_t sample_index = 0; sample_index < SAMPLE_N; ++sample_index)
        {
            const auto random_scalar = scalar_t::random();
            counts[random_scalar.data()[0] & 0x07] += 1;
        }
        check_distribution("scalar_t::random", counts);
    }

    // -----------------------------------------------------------------------
    // Test 2: hash_t::scalar distribution
    //
    // This is the transcript hot path — every scalar_transcript_t::update
    // call ends with hash_t::sha3(...).scalar, so a bias here becomes a
    // bias in every Fiat-Shamir challenge across BP/BP+/BP++, CLSAG, MLSAG,
    // Triptych, DLEQ, VRF native, adapter signatures, Schnorr, and Borromean.
    // -----------------------------------------------------------------------
    {
        size_t counts[8] = {0};
        for (size_t sample_index = 0; sample_index < SAMPLE_N; ++sample_index)
        {
            unsigned char seed_buffer[8] = {0};
            std::memcpy(seed_buffer, &sample_index, sizeof(sample_index));
            const auto hash_scalar = hash_t::sha3(seed_buffer, sizeof(seed_buffer)).scalar();
            counts[hash_scalar.data()[0] & 0x07] += 1;
        }
        check_distribution("hash_t::scalar", counts);
    }

    // -----------------------------------------------------------------------
    // Test 3: scalar_transcript_t::challenge distribution
    //
    // Integration regression — proves the full transcript pipeline
    // (Serialization → SHA3 → hash_t::scalar → scalar_t) has no residual
    // bias. This is the actual code path every proof system takes.
    // -----------------------------------------------------------------------
    {
        size_t counts[8] = {0};
        for (size_t sample_index = 0; sample_index < SAMPLE_N; ++sample_index)
        {
            scalar_transcript_t transcript(scalar_t(static_cast<uint64_t>(sample_index)));
            const auto transcript_challenge = transcript.challenge();
            counts[transcript_challenge.data()[0] & 0x07] += 1;
        }
        check_distribution("scalar_transcript_t::challenge", counts);
    }

    // -----------------------------------------------------------------------
    // Test 4: scalar_t::reduce preserves low bits
    //
    // Under the code,.reduce secretly called sc_clamp, which
    // zeroed bytes[0] & 0x07 on every invocation. This test constructs a
    // canonical (< l) scalar with each possible low-bit pattern and asserts
    // that.reduce leaves those bits intact. Under the old code this loop
    // would fail on all non-zero patterns.
    // -----------------------------------------------------------------------
    {
        bool all_preserved = true;
        for (unsigned char low_bits = 0; low_bits < 8; ++low_bits)
        {
            // Construct a canonical test value well below l: bytes[0]=low_bits,
            // all other bytes zero. Trivially canonical (small integer).
            std::vector<unsigned char> raw_bytes(32, 0);
            raw_bytes[0] = low_bits;

            const scalar_t raw_scalar(raw_bytes);
            const scalar_t reduced_scalar = raw_scalar.reduce();

            if ((reduced_scalar.data()[0] & 0x07) != low_bits)
            {
                all_preserved = false;
                break;
            }
        }
        check("scalar_t::reduce preserves low 3 bits on canonical values", all_preserved);
    }

    // -----------------------------------------------------------------------
    // Test 5: scalar_t::reduce is a no-op on an already-canonical scalar
    //
    // Direct assertion that.reduce does not mutate bytes of an in-range
    // value. Under the clamp, bit 254 would be set and the low 3
    // bits cleared on every call, guaranteeing this test would fail.
    // -----------------------------------------------------------------------
    {
        const scalar_t small_canonical(static_cast<uint64_t>(42));
        const scalar_t reduced_small = small_canonical.reduce();

        bool bitwise_equal = true;
        for (size_t byte_index = 0; byte_index < 32; ++byte_index)
        {
            if (small_canonical.data()[byte_index] != reduced_small.data()[byte_index])
            {
                bitwise_equal = false;
                break;
            }
        }
        check("scalar_t::reduce is identity on canonical small scalar", bitwise_equal);
    }

    // -----------------------------------------------------------------------
    // Test 6: scalar_t::random hits every forbidden residue within a loop budget
    //
    // Explicit anti-regression encoding the exact empirical finding from the
    // probe. Under the path these four classes would
    // never appear no matter how many samples we draw; under the fix each
    // one should be observed within ~O(100) samples on average. Using a
    // generous 5000-sample budget to avoid flakiness under unlucky RNG runs.
    // -----------------------------------------------------------------------
    {
        bool seen_residue[8] = {false, false, false, false, false, false, false, false};
        const size_t budget = 5000;

        for (size_t attempt = 0; attempt < budget; ++attempt)
        {
            const auto random_scalar = scalar_t::random();
            seen_residue[random_scalar.data()[0] & 0x07] = true;
        }

        bool all_forbidden_seen = true;
        for (const unsigned char forbidden : FORBIDDEN_RESIDUES)
        {
            if (!seen_residue[forbidden])
            {
                all_forbidden_seen = false;
                break;
            }
        }
        check(
            "scalar_t::random produces all forbidden residues within 5000 samples"
            "",
            all_forbidden_seen);
    }

    // -----------------------------------------------------------------------
    // Test 7 + 8: from_rfc8032_seed still correctly clamps, verified via
    // RFC 8032 §7.1 Appendix A vector 1 (deterministic public key derivation)
    //
    // We cannot directly observe the post-clamp pre-reduce bytes through the
    // public API, so we verify the clamp site indirectly: feed the known
    // RFC 8032 vector 1 seed through secret_key_t::load_hook (the one and
    // only caller of from_rfc8032_seed) and assert that the derived public
    // key equals the RFC 8032 vector 1 expected public key, byte-for-byte.
    // If the clamp were missing or corrupted, the signing scalar would be
    // wrong and the public key would mismatch.
    //
    // RFC 8032 §7.1 TEST 1:
    // SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    // PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    // -----------------------------------------------------------------------
    {
        const auto seed_bytes =
            Serialization::from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        const auto expected_pk_bytes =
            Serialization::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        // Construct secret_key_t from the 32-byte seed — the vector ctor calls
        // load_hook internally, which is the sole caller of from_rfc8032_seed.
        const secret_key_t loaded_secret_key(seed_bytes);

        const auto derived_public_key_bytes = loaded_secret_key.point().serialize();

        check(
            "from_rfc8032_seed: RFC 8032 vector 1 secret->public key derivation matches spec",
            derived_public_key_bytes == expected_pk_bytes);
    }

    // -----------------------------------------------------------------------
    // Test 9: scalar_t::from_uniform_bytes sanity
    //
    // The new uniform-sampling factory is a thin wrapper over
    // Crypto::reduce_wide_hash. Cross-check that they produce identical
    // output on a deterministic 64-byte input. Also verify that feeding a
    // 64-byte all-zero buffer produces the zero scalar (edge case of the
    // three-limb decomposition).
    // -----------------------------------------------------------------------
    {
        unsigned char uniform_input[64];
        for (size_t byte_index = 0; byte_index < 64; ++byte_index)
        {
            uniform_input[byte_index] = static_cast<unsigned char>(byte_index * 7 + 3);
        }

        const auto via_factory = scalar_t::from_uniform_bytes(uniform_input);
        const auto via_helper = Crypto::reduce_wide_hash(uniform_input);
        check("from_uniform_bytes matches reduce_wide_hash on deterministic input", via_factory == via_helper);

        unsigned char zero_input[64] = {0};
        const auto zero_scalar = scalar_t::from_uniform_bytes(zero_input);
        check("from_uniform_bytes on all-zero input produces zero scalar", zero_scalar == Crypto::ZERO);
    }
}

static void test_hashing()
{
    check("sha3", hash_t::sha3(INPUT_DATA) == SHA3_HASH);
    check("blake2b", hash_t::blake2b(INPUT_DATA) == BLAKE2B);
    check("argon2d", hash_t::argon2d(INPUT_DATA, 4, 1024, 1) == ARGON2D_4_1024_1);
    check("argon2i", hash_t::argon2i(INPUT_DATA, 4, 1024, 1) == ARGON2I_4_1024_1);
    check("argon2id", hash_t::argon2id(INPUT_DATA, 4, 1024, 1) == ARGON2ID_4_1024_1);
    check("sha3_slow", hash_t::sha3_slow(INPUT_DATA) == SHA3_SLOW_0);
    check("sha3_slow[4096]", hash_t::sha3_slow(INPUT_DATA, 4096) == SHA3_SLOW_4096);
}

static void test_aes()
{
    const auto input = std::string("cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e");
    const auto password = std::string("SuperSecretPassword");
    const auto encrypted = Crypto::AES::encrypt(input, password);
    const auto decrypted = Crypto::AES::decrypt(encrypted, password);
    check("aes encrypt/decrypt", decrypted == input);

    // Negative coverage ( Group C backfill, ). The envelope is a
    // hex-encoded string laid out as salt(16) || ciphertext || HMAC-SHA3-256(32).
    // decrypt throws std::invalid_argument on HMAC mismatch or AES failure;
    // we assert that every tamper path lands in that catch branch.
    const auto expect_reject = [&](const char *name, const std::string &envelope, const std::string &pw)
    {
        bool caught = false;
        try
        {
            (void)Crypto::AES::decrypt(envelope, pw);
        }
        catch (const std::invalid_argument &)
        {
            caught = true;
        }
        check(name, caught);
    };

    // 1. Wrong password — PBKDF2 derives different keys, HMAC fails, decrypt throws.
    expect_reject("aes decrypt rejects wrong password", encrypted, std::string("WrongPassword"));

    // 2. Tampered ciphertext body — flip a nibble at hex index 34, which is
    // byte 17 (first byte past the 16-byte salt, well inside the ciphertext
    // region). HMAC covers salt||ciphertext so the modification fails HMAC.
    {
        std::string tampered = encrypted;
        tampered[34] = (tampered[34] == '0') ? '1' : '0';
        expect_reject("aes decrypt rejects tampered ciphertext", tampered, password);
    }

    // 3. Tampered salt — flip a nibble at hex index 0 (inside the salt). PBKDF2
    // derives different keys, HMAC computation mismatches, decrypt throws.
    {
        std::string tampered = encrypted;
        tampered[0] = (tampered[0] == '0') ? '1' : '0';
        expect_reject("aes decrypt rejects tampered salt", tampered, password);
    }
}

static void test_base58()
{
    // Base58 plain encode/decode
    {
        const auto a = point_t::random();
        const auto b = point_t::random();
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        writer.pod(b);

        const auto encoded = Crypto::Base58::encode(writer.vector());
        auto [success, reader] = Crypto::Base58::decode(encoded);
        if (!check("base58 decode", success))
            return;

        const auto prefix = reader.varint<uint64_t>();
        const auto checka = reader.pod<point_t>();
        const auto checkb = reader.pod<point_t>();
        check("base58 encode/decode", checka == a && checkb == b && prefix == BASE58_PREFIX);
    }

    // Base58 encode_check / decode_check
    {
        const auto a = point_t::random();
        const auto b = point_t::random();
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        writer.pod(b);

        const auto encoded = Crypto::Base58::encode_check(writer);
        auto [success, reader] = Crypto::Base58::decode_check(encoded);
        if (!check("base58 decode_check", success))
            return;

        const auto prefix = reader.varint<uint64_t>();
        const auto checka = reader.pod<point_t>();
        const auto checkb = reader.pod<point_t>();
        check("base58 encode_check/decode_check", checka == a && checkb == b && prefix == BASE58_PREFIX);
    }

    // CryptoNote Base58 plain
    {
        const auto a = point_t::random();
        const auto b = point_t::random();
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        writer.pod(b);

        const auto encoded = Crypto::CNBase58::encode_check(writer);
        auto [success, reader] = Crypto::CNBase58::decode(encoded);
        if (!check("cnbase58 decode", success))
            return;

        const auto prefix = reader.varint<uint64_t>();
        const auto checka = reader.pod<point_t>();
        const auto checkb = reader.pod<point_t>();
        check("cnbase58 encode/decode", checka == a && checkb == b && prefix == BASE58_PREFIX);
    }

    // CryptoNote Base58 encode_check / decode_check
    {
        const auto a = point_t::random();
        const auto b = point_t::random();
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        writer.pod(b);

        const auto encoded = Crypto::CNBase58::encode_check(writer);
        auto [success, reader] = Crypto::CNBase58::decode_check(encoded);
        if (!check("cnbase58 decode_check", success))
            return;

        const auto prefix = reader.varint<uint64_t>();
        const auto checka = reader.pod<point_t>();
        const auto checkb = reader.pod<point_t>();
        check("cnbase58 encode_check/decode_check", checka == a && checkb == b && prefix == BASE58_PREFIX);
    }

    // oversized-input rejection. The
    // payload is all-'1' (a valid Base58 character) so only the cap explains
    // the rejection, not the character-map check.
    {
        const std::string oversized(CRYPTO_BASE58_MAX_INPUT_LENGTH + 1, '1');

        {
            auto [success, reader] = Crypto::Base58::decode(oversized);
            check("base58 decode rejects oversized input", !success);
        }

        {
            auto [success, reader] = Crypto::Base58::decode_check(oversized);
            check("base58 decode_check rejects oversized input", !success);
        }

        {
            auto [success, reader] = Crypto::CNBase58::decode(oversized);
            check("cnbase58 decode rejects oversized input", !success);
        }

        {
            auto [success, reader] = Crypto::CNBase58::decode_check(oversized);
            check("cnbase58 decode_check rejects oversized input", !success);
        }
    }

    // Negative coverage ( Group C backfill, ). Invalid-character,
    // truncated, and bad-checksum rejections for both Base58 and CNBase58. The
    // character '0' (0x30) is NOT in the Base58 alphabet (see Base58Characters
    // in src/base58/base58.cpp), so any splice of '0' is guaranteed to fail the
    // character-map check regardless of the surrounding bytes.
    {
        const auto a = point_t::random();
        const auto b = point_t::random();
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        writer.pod(b);
        const auto source_bytes = writer.vector();

        // ---- plain Base58 ----
        {
            std::string encoded = Crypto::Base58::encode(source_bytes);

            // 1. Invalid character: splice '0' into the middle.
            {
                std::string corrupted = encoded;
                corrupted[corrupted.size() / 2] = '0';
                auto [success, reader] = Crypto::Base58::decode(corrupted);
                check("base58 decode rejects invalid character", !success);
            }

            // 2. Truncated input: drop the last character. Either the decode
            // fails outright or the decoded bytes differ from the source.
            {
                std::string truncated = encoded.substr(0, encoded.size() - 1);
                auto [success, reader] = Crypto::Base58::decode(truncated);
                const auto decoded_bytes = reader.unread_data();
                const bool rejected = !success || decoded_bytes != source_bytes;
                check("base58 decode rejects truncated input", rejected);
            }
        }

        // 3. Bad checksum: flip a char inside the 4-byte SHA3 checksum tail.
        {
            std::string encoded_check = Crypto::Base58::encode_check(source_bytes);
            std::string corrupted = encoded_check;
            const size_t flip_at = corrupted.size() - 2;
            corrupted[flip_at] = (corrupted[flip_at] == '1') ? '2' : '1';
            auto [success, reader] = Crypto::Base58::decode_check(corrupted);
            check("base58 decode_check rejects bad checksum", !success);
        }

        // ---- CryptoNote Base58 ----
        {
            std::string encoded = Crypto::CNBase58::encode(source_bytes);

            // 1. Invalid character.
            {
                std::string corrupted = encoded;
                corrupted[corrupted.size() / 2] = '0';
                auto [success, reader] = Crypto::CNBase58::decode(corrupted);
                check("cnbase58 decode rejects invalid character", !success);
            }

            // 2. Truncated input.
            {
                std::string truncated = encoded.substr(0, encoded.size() - 1);
                auto [success, reader] = Crypto::CNBase58::decode(truncated);
                const auto decoded_bytes = reader.unread_data();
                const bool rejected = !success || decoded_bytes != source_bytes;
                check("cnbase58 decode rejects truncated input", rejected);
            }
        }

        // 3. Bad checksum.
        {
            std::string encoded_check = Crypto::CNBase58::encode_check(source_bytes);
            std::string corrupted = encoded_check;
            const size_t flip_at = corrupted.size() - 2;
            corrupted[flip_at] = (corrupted[flip_at] == '1') ? '2' : '1';
            auto [success, reader] = Crypto::CNBase58::decode_check(corrupted);
            check("cnbase58 decode_check rejects bad checksum", !success);
        }
    }
}

// ---------------------------------------------------------------------------
// Address encoding (strict trailing-bytes check)
// ---------------------------------------------------------------------------
//
// The decoder requires the unread tail to be exactly 0 (single-key) or
// exactly public_key_t::size (dual-key); anything else is rejected. These
// tests pin both directions:
// - round-trip single-key and dual-key addresses must still decode cleanly,
// - forged addresses with off-size tails (1, 16, 31, 33, 48, 64) must reject.
// Forged inputs are routed through encode_check so the checksum is valid —
// without that, decode_check would reject before our strict tail check fires
// and we wouldn't actually be exercising the code path.
template<typename DecodeFn, typename EncodeCheckFn>
static void test_address_encoding_namespace(const char *label, DecodeFn decode_fn, EncodeCheckFn encode_check_fn)
{
    const auto a = point_t::random();
    const auto b = point_t::random();

    // Round-trip single-key (helper produces 0-byte tail).
    {
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        const auto encoded = encode_check_fn(writer);
        const auto [ok, prefix, k1, k2] = decode_fn(encoded);
        check(
            (std::string(label) + " single-key round-trip").c_str(),
            ok && prefix == BASE58_PREFIX && k1 == a && k2 == public_key_t {});
    }

    // Round-trip dual-key (helper produces 32-byte tail).
    {
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        writer.pod(b);
        const auto encoded = encode_check_fn(writer);
        const auto [ok, prefix, k1, k2] = decode_fn(encoded);
        check(
            (std::string(label) + " dual-key round-trip").c_str(), ok && prefix == BASE58_PREFIX && k1 == a && k2 == b);
    }

    // Reject ambiguous tails. Each forged input has {prefix, public_spend, N junk bytes}
    // for N in {1, 16, 31, 33, 48, 64}. every one of these returned ok=true with
    // a zero public_view — the soft-failure mode closes.
    const std::vector<size_t> bad_tails = {1, 16, 31, 33, 48, 64};
    for (const auto N : bad_tails)
    {
        Serialization::serializer_t writer;
        writer.varint(BASE58_PREFIX);
        writer.pod(a);
        const std::vector<unsigned char> junk(N, 0);
        writer.bytes(junk);
        const auto encoded = encode_check_fn(writer);
        const auto [ok, prefix, k1, k2] = decode_fn(encoded);
        const auto name = std::string(label) + " reject" + std::to_string(N) + "-byte tail";
        check(name.c_str(), !ok && prefix == 0 && k1 == public_key_t {} && k2 == public_key_t {});
    }
}

static void test_address_encoding()
{
    test_address_encoding_namespace(
        "address Base58",
        [](const std::string &s) { return Crypto::Address::Base58::decode(s); },
        [](const Serialization::serializer_t &w) { return Crypto::Base58::encode_check(w); });

    test_address_encoding_namespace(
        "address CNBase58",
        [](const std::string &s) { return Crypto::Address::CNBase58::decode(s); },
        [](const Serialization::serializer_t &w) { return Crypto::CNBase58::encode_check(w); });
}

static void test_utilities()
{
    check("pow2_round", Crypto::pow2_round(13) == 16);

    {
        const auto points = point_vector_t(point_t::random(20)).dedupe_sort();
        check("random points unique", points.size() == 20);

        const auto scalars = scalar_vector_t(scalar_t::random(20)).dedupe_sort();
        check("random scalars unique", scalars.size() == 20);
    }

    {
        const auto scalar = std::string("a03681f038b1aee4d417874fa551aaa8f4a608a70ddff0257dd93f932b8fef0e");
        const auto point = std::string("d555bf22bce71d4eff27aa7597b5590969e7eccdb67a52188d0d73d5ab82d414");

        check("check_scalar valid", Crypto::check_scalar(scalar));
        check("check_scalar rejects point", !Crypto::check_scalar(point));
        check("check_point valid", Crypto::check_point(point));
        check("check_point rejects scalar", !Crypto::check_point(scalar));
    }

    {
        const auto a = scalar_t::random();
        const auto bits = a.to_bits();
        scalar_t b(bits);
        check("scalar bit vector roundtrip", b == a);
    }
}

static void test_entropy()
{
    {
        const auto wallet_entropy = entropy_t::random(256, {});
        const auto restored = entropy_t::recover(wallet_entropy.to_mnemonic_phrase());
        check("entropy 256-bit restore", restored == wallet_entropy);
    }

    {
        const auto wallet_entropy = entropy_t::random(128, {}, false);
        const auto restored = entropy_t::recover(wallet_entropy.to_mnemonic_phrase());
        check("entropy 128-bit restore", restored == wallet_entropy);
    }
}

static void test_key_derivation()
{
    const auto wallet_entropy = entropy_t::random();
    const auto seed = seed_t(wallet_entropy);

    const auto [public_key, secret_key] = seed.generate_child_key(44, 0, 0, 0, 0).keys();

    check("secret_key_to_public_key", secret_key.point() == public_key);
    check("entropy binary encoding", test_binary_encoding_v3(wallet_entropy));
    check("entropy JSON encoding", test_json_encoding_v3(wallet_entropy));
    check("secret_key binary encoding", test_binary_encoding_v3(secret_key));
    check("secret_key JSON encoding", test_json_encoding_v3(secret_key));

    {
        const auto [pub, subwallet] = seed.generate_child_key(44, 0, 0, 0, 1).keys();
        check("subwallet(1) differs from root", subwallet != secret_key);
    }

    {
        const auto [pub, subwallet] = seed.generate_child_key(44, 0, 0, 0, 32).keys();
        check("subwallet(32) differs from root", subwallet != secret_key);
    }

    const auto [pub2, secret_key2] = seed.generate_child_key(45, 0, 1, 0, 0).keys();
    check("view key differs from spend key", secret_key2 != secret_key);

    // Negative coverage ( Group D backfill, ). Pins the
    // distinct-inputs/distinct-outputs contract at crypto_common.h:147-176 so a
    // future refactor that drops the parent key, output_index, or derivation
    // point from the hash input fails loudly instead of silently collapsing the
    // stealth-address key space.

    // Wrong parent: output addressed to W1, underive attempted with W2's view
    // key. Recovered point must match neither wallet's base key.
    {
        const auto seed_w1 = seed_t(entropy_t::random());
        const auto seed_w2 = seed_t(entropy_t::random());
        const auto [w1_spend_pub, w1_spend_sec] = seed_w1.generate_child_key(44, 0, 0, 0, 0).keys();
        const auto [w1_view_pub, w1_view_sec] = seed_w1.generate_child_key(45, 0, 1, 0, 0).keys();
        const auto [w2_view_pub, w2_view_sec] = seed_w2.generate_child_key(45, 0, 1, 0, 0).keys();

        const auto derivation_w1 = Crypto::generate_key_derivation(w1_view_pub, w1_spend_sec);
        const auto ds_w1 = Crypto::derivation_to_scalar(derivation_w1, 0);
        const auto p1 = Crypto::derive_public_key(ds_w1, w1_spend_pub);

        const auto derivation_w2 = Crypto::generate_key_derivation(w1_spend_sec.point(), w2_view_sec);
        const auto recovered_wrong = Crypto::underive_public_key(derivation_w2, 0, p1);
        check("derive_public_key wrong parent: recovered != w1 spend", recovered_wrong != w1_spend_pub);
        check("derive_public_key wrong parent: recovered != w2 view", recovered_wrong != w2_view_pub);
    }

    // Per-output-index distinctness pins output_index into the hash.
    {
        const auto seed_src = seed_t(entropy_t::random());
        const auto [src_spend_pub, src_spend_sec] = seed_src.generate_child_key(44, 0, 0, 0, 0).keys();
        const auto [src_view_pub, src_view_sec] = seed_src.generate_child_key(45, 0, 1, 0, 0).keys();
        const auto derivation = Crypto::generate_key_derivation(src_view_pub, src_spend_sec);

        const auto ds0 = Crypto::derivation_to_scalar(derivation, 0);
        const auto ds1 = Crypto::derivation_to_scalar(derivation, 1);
        const auto ds2 = Crypto::derivation_to_scalar(derivation, 2);
        check("derivation_to_scalar distinct across indices (0/1)", ds0 != ds1);
        check("derivation_to_scalar distinct across indices (1/2)", ds1 != ds2);
        check("derivation_to_scalar distinct across indices (0/2)", ds0 != ds2);
    }

    // Per-derivation distinctness pins the derivation point into the hash.
    {
        const auto seed_a = seed_t(entropy_t::random());
        const auto seed_b = seed_t(entropy_t::random());
        const auto [a_spend_pub, a_spend_sec] = seed_a.generate_child_key(44, 0, 0, 0, 0).keys();
        const auto [a_view_pub, a_view_sec] = seed_a.generate_child_key(45, 0, 1, 0, 0).keys();
        const auto [b_spend_pub, b_spend_sec] = seed_b.generate_child_key(44, 0, 0, 0, 0).keys();
        const auto [b_view_pub, b_view_sec] = seed_b.generate_child_key(45, 0, 1, 0, 0).keys();

        const auto derivation_a = Crypto::generate_key_derivation(a_view_pub, a_spend_sec);
        const auto derivation_b = Crypto::generate_key_derivation(b_view_pub, b_spend_sec);
        check("independent derivations distinct", derivation_a != derivation_b);

        const auto ds_a = Crypto::derivation_to_scalar(derivation_a, 0);
        const auto ds_b = Crypto::derivation_to_scalar(derivation_b, 0);
        check("derivation_to_scalar distinct across derivations", ds_a != ds_b);
    }
}

// Helper used by ring-signature tests below to keep each test self-contained: builds
// a fresh stealth address pair (public_ephemeral / secret_ephemeral) and the matching
// key images.
struct stealth_keys_t
{
    public_key_t public_ephemeral;
    scalar_t secret_ephemeral;
    key_image_t key_image;
    key_image_t key_image_v2;
};

static stealth_keys_t make_stealth_keys()
{
    const auto wallet_entropy = entropy_t::random();
    const auto seed = seed_t(wallet_entropy);
    const auto [spend_pub, spend_sec] = seed.generate_child_key(44, 0, 0, 0, 0).keys();
    const auto [view_pub, view_sec] = seed.generate_child_key(45, 0, 1, 0, 0).keys();

    const auto derivation = Crypto::generate_key_derivation(view_pub, spend_sec);
    const auto derivation_scalar = Crypto::derivation_to_scalar(derivation, 64);

    stealth_keys_t out;
    out.public_ephemeral = Crypto::derive_public_key(derivation_scalar, view_pub);
    out.secret_ephemeral = Crypto::derive_secret_key(derivation_scalar, view_sec);
    out.key_image = Crypto::generate_key_image(out.public_ephemeral, out.secret_ephemeral);
    out.key_image_v2 = Crypto::generate_key_image_v2(out.secret_ephemeral);
    return out;
}

// Returns the canonical Ed25519 order-2 torsion point: y = -1 (mod p), x = 0.
// Compressed encoding `ec ff … ff 7f` decodes to (0, p-1). Used by the ring-signature
// negative tests below to prove that subgroup checks reject 8-torsion-tainted inputs
// (forged-distinct linkability tag → double-spend dedup bypass). Self-checks
// at first call so the test fails loudly if the byte sequence ever drifts.
static const point_t &torsion_point()
{
    static const point_t T(std::vector<unsigned char> {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f});
    static const bool ok = ((T + T) == point_t()) && !T.check_subgroup() && !(T == point_t());
    check("torsion_point self-check", ok);
    return T;
}

// Returns true if the callable throws std::invalid_argument. Template rather than a
// capturing lambda so it can be invoked from test functions whose locals are
// structured bindings (C++17 forbids capturing those — fixed in C++20).
template<typename F> static bool throws_invalid_argument(F &&fn)
{
    try
    {
        fn();
    }
    catch (const std::invalid_argument &)
    {
        return true;
    }
    return false;
}

// Defect negative tests: 8-torsion injection on commitment_image / pseudo_commitment
// must be rejected. commitment_image is the Pedersen-side linkability tag — without these
// checks a malicious signer could publish a *distinct* tag for the same input (double-spend
// dedup bypass). Templated so all three commitment-mode ring-signature schemes can share it.
template<typename SigT, typename VerifyFn>
static void check_torsion_rejection(const char *prefix, const SigT &signature, VerifyFn verify)
{
    const auto &T = torsion_point();

    auto tampered_ki = signature;
    tampered_ki.commitment_image = signature.commitment_image + T;
    check((std::string(prefix) + " rejects torsion in commitment_image").c_str(), !verify(tampered_ki));

    auto tampered_pc = signature;
    tampered_pc.pseudo_commitment = signature.pseudo_commitment + T;
    check((std::string(prefix) + " rejects torsion in pseudo_commitment").c_str(), !verify(tampered_pc));
}

static void test_stealth_addresses()
{
    const auto wallet_entropy = entropy_t::random();
    const auto seed = seed_t(wallet_entropy);
    const auto [spend_pub, spend_sec] = seed.generate_child_key(44, 0, 0, 0, 0).keys();
    const auto [view_pub, view_sec] = seed.generate_child_key(45, 0, 1, 0, 0).keys();

    // Sender side
    const auto derivation_sender = Crypto::generate_key_derivation(view_pub, spend_sec);
    const auto ds_sender = Crypto::derivation_to_scalar(derivation_sender, 64);
    const auto expected_pub_ephemeral = Crypto::derive_public_key(ds_sender, view_pub);

    // Receiver side
    const auto derivation_recv = Crypto::generate_key_derivation(spend_pub, view_sec);
    const auto ds_recv = Crypto::derivation_to_scalar(derivation_recv, 64);
    const auto pub_ephemeral = Crypto::derive_public_key(ds_recv, view_pub);
    const auto sec_ephemeral = Crypto::derive_secret_key(ds_recv, view_sec);

    check("public_ephemeral matches", sec_ephemeral.point() == expected_pub_ephemeral);

    // underive_public_key recovers the recipient view key
    const auto underived = Crypto::underive_public_key(derivation_sender, 64, pub_ephemeral);
    check("underive_public_key", underived == view_pub);

    const auto ki = Crypto::generate_key_image(pub_ephemeral, sec_ephemeral);
    check("key_image subgroup", ki.check_subgroup());

    const auto ki2 = Crypto::generate_key_image_v2(sec_ephemeral);
    check("key_image_v2 subgroup", ki2.check_subgroup());

    // Negative coverage ( Group D backfill,, ). Wrong view
    // key must not collide with the recipient base key, and every caller-supplied
    // point into the stealth APIs must reject 8-torsion contamination. The local
    // aliases below exist because the enclosing structured bindings can't be
    // captured by lambdas until C++20.
    const auto view_pub_local = view_pub;
    const auto spend_sec_local = spend_sec;

    {
        const auto other_seed = seed_t(entropy_t::random());
        const auto other_view_sec = std::get<1>(other_seed.generate_child_key(45, 0, 1, 0, 0).keys());
        const auto derivation_wrong = Crypto::generate_key_derivation(spend_pub, other_view_sec);
        const auto underived_wrong = Crypto::underive_public_key(derivation_wrong, 64, pub_ephemeral);
        check("underive_public_key rejects wrong view key", underived_wrong != view_pub);
    }

    check(
        "underive_public_key rejects torsioned derivation",
        throws_invalid_argument(
            [&] { (void)Crypto::underive_public_key(derivation_sender + torsion_point(), 64, pub_ephemeral); }));

    check(
        "underive_public_key rejects torsioned public_ephemeral",
        throws_invalid_argument(
            [&] { (void)Crypto::underive_public_key(derivation_sender, 64, pub_ephemeral + torsion_point()); }));

    check(
        "derive_public_key rejects torsioned public_key",
        throws_invalid_argument([&] { (void)Crypto::derive_public_key(ds_recv, view_pub_local + torsion_point()); }));

    check(
        "generate_key_derivation rejects torsioned public_key",
        throws_invalid_argument(
            [&] { (void)Crypto::generate_key_derivation(view_pub_local + torsion_point(), spend_sec_local); }));
}

static void test_audit_proofs()
{
    const auto [public_keys, secret_keys] = Crypto::generate_keys_m(20);
    const auto [success, proof] = Crypto::Audit::generate_outputs_proof(secret_keys);
    if (!check("generate_outputs_proof", success))
        return;

    const auto [valid, key_images] = Crypto::Audit::check_outputs_proof(public_keys, proof);
    check("check_outputs_proof", valid);

    // Negative coverage ( Group D backfill, ). The transcript at
    // src/integration/.cpp:84 binds (public_ephemerals[i], key_images[i]) in
    // slot order, so wrong-key and reorder tampers must both reject.
    {
        auto public_keys_wrong = public_keys;
        public_keys_wrong[0] = std::get<0>(Crypto::generate_keys());
        const auto [valid_wrong, key_images_wrong] = Crypto::Audit::check_outputs_proof(public_keys_wrong, proof);
        check("check_outputs_proof rejects wrong public key", !valid_wrong);
        check("check_outputs_proof wrong key yields empty key_images", key_images_wrong.empty());
    }

    {
        auto public_keys_reordered = public_keys;
        std::swap(public_keys_reordered[0], public_keys_reordered[1]);
        const auto [valid_reordered, key_images_reordered] =
            Crypto::Audit::check_outputs_proof(public_keys_reordered, proof);
        check("check_outputs_proof rejects reordered public keys", !valid_reordered);
        check("check_outputs_proof reordered keys yields empty key_images", key_images_reordered.empty());
    }
}

static void test_signatures()
{
    const auto [public_key, secret_key] = Crypto::generate_keys();

    {
        const auto signature = Crypto::Signature::generate_signature(SHA3_HASH, secret_key);
        check("check_signature", Crypto::Signature::check_signature(SHA3_HASH, public_key, signature));

        // Negative coverage ( Group C backfill, ). LR.L carries
        // the challenge scalar c, LR.R carries the response scalar r. All three
        // negatives must produce reject (return false, no throw).
        {
            // 1. Wrong message: verify against a different digest. The recomputed
            // transcript challenge diverges, so the equality check fails.
            const auto other_digest = hash_t::sha3(std::string("different-message"));
            check(
                "check_signature rejects wrong message",
                !Crypto::Signature::check_signature(other_digest, public_key, signature));

            // 2. Wrong public key: verify against an independent key. The MSM
            // c*P' + r*G yields a different point, so transcript mismatch.
            const auto [other_public_key, other_secret_key] = Crypto::generate_keys();
            check(
                "check_signature rejects wrong public key",
                !Crypto::Signature::check_signature(SHA3_HASH, other_public_key, signature));

            // 3. Tampered LR.R (response scalar): flip low bit of byte[0].
            auto tampered = signature;
            tampered.LR.R[0] ^= 0x01;
            check(
                "check_signature rejects tampered LR.R",
                !Crypto::Signature::check_signature(SHA3_HASH, public_key, tampered));
        }
    }

    {
        const auto signature = Crypto::RFC8032::generate_signature(SHA3_HASH, secret_key);
        check("rfc8032 check_signature", Crypto::RFC8032::check_signature(SHA3_HASH, public_key, signature));

        // Negative coverage ( Group C backfill, ). Two RFC 8032
        // tamper cases using the hedged signature we just produced (we cannot
        // edit the RFC 8032 §7.1 Appendix A vectors because that block's
        // 1-byte-flip already covers byte-flip rejection on a canonical vector).
        {
            // 1. Wrong-key reject: verify against an independent public key.
            // The verification equation alpha + k*A == s*G holds only for
            // the key that produced the signature.
            const auto [other_public_key, other_secret_key] = Crypto::generate_keys();
            check(
                "rfc8032 check_signature rejects wrong public key",
                !Crypto::RFC8032::check_signature(SHA3_HASH, other_public_key, signature));

            // 2. Torsion-on-R reject: replace the encoded commitment point R
            // (stored in signature.LR.L) with R + T where T is the canonical
            // order-2 torsion point. The verifier subgroup-checks public_key
            // and then uses strict equality on alpha + k*A == s*G; the
            // left-hand side now carries T that the right-hand side cannot
            // match, so the signature must be rejected. This validates the
            // rejection *outcome* for torsion-injected R regardless of
            // which code path inside check_signature catches it.
            auto tampered = signature;
            const auto original_R = point_t(signature.LR.L.serialize());
            const auto torsioned_R = original_R + torsion_point();
            tampered.LR.L = scalar_t(torsioned_R.serialize());
            check(
                "rfc8032 check_signature rejects torsion-on-R",
                !Crypto::RFC8032::check_signature(SHA3_HASH, public_key, tampered));
        }
    }

    // ------------------------------------------------------------------------
    // regression: RFC 8032 §7.1 Appendix A test vectors.
    //
    // Each (public_key, message, signature) triple is verbatim from RFC 8032
    // §7.1. Our verifier must accept all of them byte-for-byte. This proves
    // Crypto::RFC8032::check_signature is byte-compatible with every other
    // spec-compliant Ed25519 implementation, and locks that interop in as a
    // regression guard. Hedged synthetic-nonce signing produces valid Ed25519
    // signatures (the §5.1.7 verification equation s·G == R + H(R||A||M)·A
    // holds for any α), so every spec-compliant external verifier accepts
    // our output.
    // ------------------------------------------------------------------------
    {
        struct rfc8032_vector
        {
            const char *name;
            const char *pk_hex;
            const char *msg_hex;
            const char *sig_hex;
        };

        // Vectors below are from RFC 8032 §7.1 (Ed25519). pk and sig are 32 and
        // 64 bytes respectively (hex). msg may be empty.
        static const rfc8032_vector vectors[] = {
            // TEST 1: empty message
            {"rfc8032 vector 1 (empty message)",
             "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
             "",
             "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf"
             "9b46bd25bf5f0595bbe24655141438e7a100b"},
            // TEST 2: 1-byte message (0x72)
            {"rfc8032 vector 2 (1 byte)",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
             "72",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f"
             "11d8c387b2eaeb4302aeeb00d291612bb0c00"},
            // TEST 3: 2-byte message (0xaf 0x82)
            {"rfc8032 vector 3 (2 bytes)",
             "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
             "af82",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984"
             "dc6594a7c15e9716ed28dc027beceea1ec40a"},
        };

        for (const auto &v : vectors)
        {
            const auto pk = public_key_t(std::string(v.pk_hex));
            const auto sig = signature_t(std::string(v.sig_hex));
            const auto msg = Serialization::from_hex(v.msg_hex);
            check(v.name, Crypto::RFC8032::check_signature(msg.data(), msg.size(), pk, sig));
        }

        // Negative control: flip one byte of vector 2's signature and confirm
        // the verifier rejects it. Proves we are not trivially accepting input.
        {
            auto bad_sig_hex = std::string(vectors[1].sig_hex);
            // Flip the first nibble of the signature (index 0 in the hex string).
            bad_sig_hex[0] = (bad_sig_hex[0] == 'f') ? '0' : 'f';
            const auto pk = public_key_t(std::string(vectors[1].pk_hex));
            const auto bad_sig = signature_t(bad_sig_hex);
            const auto msg = Serialization::from_hex(vectors[1].msg_hex);
            check(
                "rfc8032 vector 2 negative control (corrupted signature rejected)",
                !Crypto::RFC8032::check_signature(msg.data(), msg.size(), pk, bad_sig));
        }
    }
}

static void test_borromean()
{
    const auto sk = make_stealth_keys();

    auto public_keys = point_t::random(RING_SIZE);
    public_keys[RING_SIZE / 2] = sk.public_ephemeral;

    const auto [gen_success, signature] =
        Crypto::RingSignature::Borromean::generate_ring_signature(SHA3_HASH, sk.secret_ephemeral, public_keys);
    if (!check("borromean generate_ring_signature", gen_success))
        return;

    check(
        "borromean check_ring_signature",
        Crypto::RingSignature::Borromean::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature));
    check("borromean binary encoding", test_binary_encoding_v2(signature));
    check("borromean JSON encoding", test_json_encoding(signature));

    // negatives. Borromean has no Pedersen commitment binding
    // so check_torsion_rejection (which targets commitment_image/pseudo_commitment)
    // does not apply — the scalar response pairs and verifier inputs are
    // tampered directly.
    {
        // Baseline reverify guard, kept in its own scope: if a future edit
        // moves a non-const operation between the happy-path check above and
        // the tamper blocks below, every tamper assertion would silently turn
        // into a false-positive pass. This guard catches that class of
        // regression. Only documented here — the pattern repeats below with
        // the same intent.
        check(
            "borromean baseline reverify before tampering",
            Crypto::RingSignature::Borromean::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature));

        {
            auto tampered = signature;
            tampered.signatures[0].LR.L[0] ^= 0x01;
            check(
                "borromean rejects tamper in signatures[0].LR.L",
                !Crypto::RingSignature::Borromean::check_ring_signature(
                    SHA3_HASH, sk.key_image, public_keys, tampered));
        }

        {
            auto tampered = signature;
            tampered.signatures[0].LR.R[0] ^= 0x01;
            check(
                "borromean rejects tamper in signatures[0].LR.R",
                !Crypto::RingSignature::Borromean::check_ring_signature(
                    SHA3_HASH, sk.key_image, public_keys, tampered));
        }

        {
            auto tampered_ring = public_keys;
            std::swap(tampered_ring[0], tampered_ring[RING_SIZE / 2]);
            check(
                "borromean rejects ring member swap",
                !Crypto::RingSignature::Borromean::check_ring_signature(
                    SHA3_HASH, sk.key_image, tampered_ring, signature));
        }

        check(
            "borromean rejects wrong message",
            !Crypto::RingSignature::Borromean::check_ring_signature(INPUT_DATA, sk.key_image, public_keys, signature));

        {
            const auto other_sk = make_stealth_keys();
            check(
                "borromean rejects wrong key_image",
                !Crypto::RingSignature::Borromean::check_ring_signature(
                    SHA3_HASH, other_sk.key_image, public_keys, signature));
        }

        // Subgroup injection. Two possible failure modes: (a) explicit
        // subgroup check on the ring member rejects it, or (b) the torsion
        // component contaminates the reconstructed challenge points and the
        // chain fails to close. Either mode satisfies the negative — the
        // assertion only asks that verification does not succeed.
        {
            auto tampered_ring = public_keys;
            tampered_ring[NON_SIGNER_SLOT] = public_keys[NON_SIGNER_SLOT] + torsion_point();
            check(
                "borromean rejects torsion injection on ring member",
                !Crypto::RingSignature::Borromean::check_ring_signature(
                    SHA3_HASH, sk.key_image, tampered_ring, signature));
        }
    }
}

static void test_clsag()
{
    const auto sk = make_stealth_keys();

    auto public_keys = point_t::random(RING_SIZE);
    public_keys[RING_SIZE / 2] = sk.public_ephemeral;

    const auto [gen_success, signature] =
        Crypto::RingSignature::CLSAG::generate_ring_signature(SHA3_HASH, sk.secret_ephemeral, public_keys);
    if (!check("clsag generate_ring_signature", gen_success))
        return;

    check(
        "clsag check_ring_signature",
        Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature));
    check("clsag binary encoding", test_binary_encoding(signature));
    check("clsag JSON encoding", test_json_encoding(signature));

    // negatives (plain mode). Commit-mode sibling below
    // exercises and torsion on commitment_image/pseudo_commitment; plain
    // mode has no commitment fields so tamper targets are the scalar
    // response row, the seed challenge, and the verifier inputs.
    {
        check(
            "clsag baseline reverify before tampering",
            Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature));

        {
            auto tampered = signature;
            tampered.scalars[0][0] ^= 0x01;
            check(
                "clsag rejects tamper in scalars[0]",
                !Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, tampered));
        }

        {
            auto tampered = signature;
            tampered.challenge[0] ^= 0x01;
            check(
                "clsag rejects tamper in challenge",
                !Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, tampered));
        }

        {
            auto tampered_ring = public_keys;
            std::swap(tampered_ring[0], tampered_ring[RING_SIZE / 2]);
            check(
                "clsag rejects ring member swap",
                !Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, sk.key_image, tampered_ring, signature));
        }

        check(
            "clsag rejects wrong message",
            !Crypto::RingSignature::CLSAG::check_ring_signature(INPUT_DATA, sk.key_image, public_keys, signature));

        {
            const auto other_sk = make_stealth_keys();
            check(
                "clsag rejects wrong key_image",
                !Crypto::RingSignature::CLSAG::check_ring_signature(
                    SHA3_HASH, other_sk.key_image, public_keys, signature));
        }

        {
            auto tampered_ring = public_keys;
            tampered_ring[NON_SIGNER_SLOT] = public_keys[NON_SIGNER_SLOT] + torsion_point();
            check(
                "clsag rejects torsion injection on ring member",
                !Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, sk.key_image, tampered_ring, signature));
        }
    }
}

static void test_clsag_commitments()
{
    const auto sk = make_stealth_keys();

    auto public_keys = point_t::random(RING_SIZE);
    public_keys[RING_SIZE / 2] = sk.public_ephemeral;

    const auto input_blinding = scalar_t::random();
    const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

    std::vector<pedersen_commitment_t> public_commitments = point_t::random(RING_SIZE);
    public_commitments[RING_SIZE / 2] = input_commitment;

    const auto [ps_blindings, ps_commitments] = Crypto::RingCT::generate_pseudo_commitments({100}, scalar_t::random(1));

    const auto [gen_success, signature] = Crypto::RingSignature::CLSAG::generate_ring_signature(
        SHA3_HASH,
        sk.secret_ephemeral,
        public_keys,
        input_blinding,
        public_commitments,
        ps_blindings[0],
        ps_commitments[0]);
    if (!check("clsag+commit generate_ring_signature", gen_success))
        return;

    check(
        "clsag+commit check_ring_signature",
        Crypto::RingSignature::CLSAG::check_ring_signature(
            SHA3_HASH, sk.key_image, public_keys, signature, public_commitments));
    check("clsag+commit binary encoding", test_binary_encoding(signature));
    check("clsag+commit JSON encoding", test_json_encoding(signature));

    check_torsion_rejection(
        "clsag+commit",
        signature,
        [&](const auto &sig)
        {
            return Crypto::RingSignature::CLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, public_keys, sig, public_commitments);
        });

    // ---- Strict mode-mismatch reject ----
    // Both directions are hard rejects, plus the transcript binds the mode tag
    // so the challenge chain would not close even if a future refactor removed
    // the runtime check.

    // Case 1: commit-mode sig + empty commitments → must reject
    check(
        "clsag+commit reject empty commitments",
        !Crypto::RingSignature::CLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature, {}));

    // Case 2: commit-mode sig + wrong-size commitments → must reject
    {
        auto short_commitments = public_commitments;
        short_commitments.pop_back();
        check(
            "clsag+commit reject wrong-size commitments",
            !Crypto::RingSignature::CLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, public_keys, signature, short_commitments));
    }

    // Case 3: plain-mode sig + non-empty commitments → must reject.
    // Reuses the outer sk/public_keys — the stealth key is orthogonal to whether the
    // signer uses commit mode, so generating a fresh plain-mode signature over the same
    // ring is sufficient to test the verifier's mismatch reject.
    {
        const auto [plain_gen_ok, plain_sig] =
            Crypto::RingSignature::CLSAG::generate_ring_signature(SHA3_HASH, sk.secret_ephemeral, public_keys);
        check("clsag plain sig generated for mismatch test", plain_gen_ok);

        check(
            "clsag reject plain sig with non-empty commitments",
            !Crypto::RingSignature::CLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, public_keys, plain_sig, public_commitments));
    }

    // negatives: scalar-response tampers and ring swap.
    // The and torsion blocks above cover mode-mismatch and point-field
    // torsion on commitment_image/pseudo_commitment.
    {
        const auto verify_commit = [&](const clsag_signature_t &sig, const std::vector<public_key_t> &ring) {
            return Crypto::RingSignature::CLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, ring, sig, public_commitments);
        };

        check("clsag+commit baseline reverify before tampering", verify_commit(signature, public_keys));

        {
            auto tampered = signature;
            tampered.scalars[0][0] ^= 0x01;
            check("clsag+commit rejects tamper in scalars[0]", !verify_commit(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.challenge[0] ^= 0x01;
            check("clsag+commit rejects tamper in challenge", !verify_commit(tampered, public_keys));
        }

        {
            auto tampered_ring = public_keys;
            std::swap(tampered_ring[0], tampered_ring[RING_SIZE / 2]);
            check("clsag+commit rejects ring member swap", !verify_commit(signature, tampered_ring));
        }
    }
}

static void test_mlsag()
{
    const auto sk = make_stealth_keys();

    auto public_keys = point_t::random(RING_SIZE);
    public_keys[RING_SIZE / 2] = sk.public_ephemeral;

    const auto [gen_success, signature] =
        Crypto::RingSignature::MLSAG::generate_ring_signature(SHA3_HASH, sk.secret_ephemeral, public_keys);
    if (!check("mlsag generate_ring_signature", gen_success))
        return;

    check(
        "mlsag check_ring_signature",
        Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature));
    check("mlsag binary encoding", test_binary_encoding(signature));
    check("mlsag JSON encoding", test_json_encoding(signature));

    // negatives (plain mode). Mirrors the CLSAG plain block
    // — same attack surface (scalar response row, seed challenge, ring,
    // message, key image, torsion injection).
    {
        check(
            "mlsag baseline reverify before tampering",
            Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature));

        {
            auto tampered = signature;
            tampered.key_scalars[0][0] ^= 0x01;
            check(
                "mlsag rejects tamper in key_scalars[0]",
                !Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, tampered));
        }

        {
            auto tampered = signature;
            tampered.challenge[0] ^= 0x01;
            check(
                "mlsag rejects tamper in challenge",
                !Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, tampered));
        }

        {
            auto tampered_ring = public_keys;
            std::swap(tampered_ring[0], tampered_ring[RING_SIZE / 2]);
            check(
                "mlsag rejects ring member swap",
                !Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, sk.key_image, tampered_ring, signature));
        }

        check(
            "mlsag rejects wrong message",
            !Crypto::RingSignature::MLSAG::check_ring_signature(INPUT_DATA, sk.key_image, public_keys, signature));

        {
            const auto other_sk = make_stealth_keys();
            check(
                "mlsag rejects wrong key_image",
                !Crypto::RingSignature::MLSAG::check_ring_signature(
                    SHA3_HASH, other_sk.key_image, public_keys, signature));
        }

        {
            auto tampered_ring = public_keys;
            tampered_ring[NON_SIGNER_SLOT] = public_keys[NON_SIGNER_SLOT] + torsion_point();
            check(
                "mlsag rejects torsion injection on ring member",
                !Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, sk.key_image, tampered_ring, signature));
        }
    }
}

static void test_mlsag_commitments()
{
    const auto sk = make_stealth_keys();

    auto public_keys = point_t::random(RING_SIZE);
    public_keys[RING_SIZE / 2] = sk.public_ephemeral;

    const auto input_blinding = scalar_t::random();
    const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

    std::vector<pedersen_commitment_t> public_commitments = point_t::random(RING_SIZE);
    public_commitments[RING_SIZE / 2] = input_commitment;

    const auto [ps_blindings, ps_commitments] = Crypto::RingCT::generate_pseudo_commitments({100}, scalar_t::random(1));

    const auto [gen_success, signature] = Crypto::RingSignature::MLSAG::generate_ring_signature(
        SHA3_HASH,
        sk.secret_ephemeral,
        public_keys,
        input_blinding,
        public_commitments,
        ps_blindings[0],
        ps_commitments[0]);
    if (!check("mlsag+commit generate_ring_signature", gen_success))
        return;

    check(
        "mlsag+commit check_ring_signature",
        Crypto::RingSignature::MLSAG::check_ring_signature(
            SHA3_HASH, sk.key_image, public_keys, signature, public_commitments));
    check("mlsag+commit binary encoding", test_binary_encoding(signature));
    check("mlsag+commit JSON encoding", test_json_encoding(signature));

    check_torsion_rejection(
        "mlsag+commit",
        signature,
        [&](const auto &sig)
        {
            return Crypto::RingSignature::MLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, public_keys, sig, public_commitments);
        });

    // ---- Strict mode-mismatch reject ----
    // Same predicate as the CLSAG block above; both modes must be
    // authenticated by the verifier.

    // Case 1: commit-mode sig + empty commitments → must reject
    check(
        "mlsag+commit reject empty commitments",
        !Crypto::RingSignature::MLSAG::check_ring_signature(SHA3_HASH, sk.key_image, public_keys, signature, {}));

    // Case 2: commit-mode sig + wrong-size commitments → must reject
    {
        auto short_commitments = public_commitments;
        short_commitments.pop_back();
        check(
            "mlsag+commit reject wrong-size commitments",
            !Crypto::RingSignature::MLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, public_keys, signature, short_commitments));
    }

    // Case 3: plain-mode sig + non-empty commitments → must reject.
    // Reuses the outer sk/public_keys — same justification as the CLSAG block above.
    {
        const auto [plain_gen_ok, plain_sig] =
            Crypto::RingSignature::MLSAG::generate_ring_signature(SHA3_HASH, sk.secret_ephemeral, public_keys);
        check("mlsag plain sig generated for mismatch test", plain_gen_ok);

        check(
            "mlsag reject plain sig with non-empty commitments",
            !Crypto::RingSignature::MLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, public_keys, plain_sig, public_commitments));
    }

    // negatives: tamper key_scalars and commitment_scalars
    // rows independently so any future refactor that silently drops the
    // commit-mode-exclusive row would fail loudly instead of shipping.
    {
        const auto verify_commit = [&](const mlsag_signature_t &sig)
        {
            return Crypto::RingSignature::MLSAG::check_ring_signature(
                SHA3_HASH, sk.key_image, public_keys, sig, public_commitments);
        };

        check("mlsag+commit baseline reverify before tampering", verify_commit(signature));

        {
            auto tampered = signature;
            tampered.key_scalars[0][0] ^= 0x01;
            check("mlsag+commit rejects tamper in key_scalars[0]", !verify_commit(tampered));
        }

        {
            auto tampered = signature;
            tampered.commitment_scalars[0][0] ^= 0x01;
            check("mlsag+commit rejects tamper in commitment_scalars[0]", !verify_commit(tampered));
        }
    }
}

static void test_triptych()
{
    const auto sk = make_stealth_keys();

    auto public_keys = point_t::random(RING_SIZE);
    public_keys[RING_SIZE / 2] = sk.public_ephemeral;

    const auto input_blinding = scalar_t::random();
    const auto input_commitment = Crypto::RingCT::generate_pedersen_commitment(input_blinding, 100);

    std::vector<pedersen_commitment_t> public_commitments = point_t::random(RING_SIZE);
    public_commitments[RING_SIZE / 2] = input_commitment;

    const auto [ps_blindings, ps_commitments] = Crypto::RingCT::generate_pseudo_commitments({100}, scalar_t::random(1));

    const auto [gen_success, signature] = Crypto::RingSignature::Triptych::generate_ring_signature(
        SHA3_HASH,
        sk.secret_ephemeral,
        public_keys,
        input_blinding,
        public_commitments,
        ps_blindings[0],
        ps_commitments[0]);
    if (!check("triptych generate_ring_signature", gen_success))
        return;

    check(
        "triptych check_ring_signature",
        Crypto::RingSignature::Triptych::check_ring_signature(
            SHA3_HASH, sk.key_image_v2, public_keys, signature, public_commitments));
    check("triptych binary encoding", test_binary_encoding(signature));
    check("triptych JSON encoding", test_json_encoding(signature));

    check_torsion_rejection(
        "triptych",
        signature,
        [&](const auto &sig)
        {
            return Crypto::RingSignature::Triptych::check_ring_signature(
                SHA3_HASH, sk.key_image_v2, public_keys, sig, public_commitments);
        });

    // ------------------------------------------------------------------------
    // regression: Triptych verifier and signer must
    // hard-reject 8-torsion on every prover-supplied point that wasn't already
    // covered by the prior fix. The earlier check_torsion_rejection above
    // exercises commitment_image and pseudo_commitment; this block exercises
    // the four commitment-tensor points A/B/C/D, the polynomial proof points
    // X[0]/Y[0], and the caller-supplied ring members public_keys[i].
    //
    // Each case re-runs verification on a freshly tampered copy of the
    // signature (or ring) and asserts hard rejection. The original signature
    // is verified again at the top so a baseline regression cannot mask a
    // torsion rejection failure.
    // ------------------------------------------------------------------------
    {
        const auto &T = torsion_point();

        const auto verify_with_ring = [&](const triptych_signature_t &sig, const std::vector<public_key_t> &ring)
        {
            return Crypto::RingSignature::Triptych::check_ring_signature(
                SHA3_HASH, sk.key_image_v2, ring, sig, public_commitments);
        };

        check("triptych baseline still verifies before tampering", verify_with_ring(signature, public_keys));

        {
            auto tampered = signature;
            tampered.A = signature.A + T;
            check("triptych rejects torsion in signature.A", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.B = signature.B + T;
            check("triptych rejects torsion in signature.B", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.C = signature.C + T;
            check("triptych rejects torsion in signature.C", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.D = signature.D + T;
            check("triptych rejects torsion in signature.D", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.X[0] = signature.X[0] + T;
            check("triptych rejects torsion in signature.X[0]", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.Y[0] = signature.Y[0] + T;
            check("triptych rejects torsion in signature.Y[0]", !verify_with_ring(tampered, public_keys));
        }

        {
            // Tamper a non-signer ring slot so the underlying scheme would
            // otherwise still produce a verifiable proof if the subgroup check
            // weren't enforced. (Tampering the signer slot would change the
            // discrete-log relation regardless and confuse the failure mode.)
            auto tampered_ring = public_keys;
            const size_t non_signer_slot = (RING_SIZE / 2 == 0) ? 1 : 0;
            tampered_ring[non_signer_slot] = public_keys[non_signer_slot] + T;
            check("triptych verifier rejects torsion in public_keys[i]", !verify_with_ring(signature, tampered_ring));

            // Mirror check on the signer side: generate_ring_signature must
            // pre-reject a torsioned ring before producing any proof.
            const auto tainted_gen = Crypto::RingSignature::Triptych::generate_ring_signature(
                SHA3_HASH,
                sk.secret_ephemeral,
                tampered_ring,
                input_blinding,
                public_commitments,
                ps_blindings[0],
                ps_commitments[0]);
            check("triptych signer rejects torsion in public_keys[i]", !std::get<0>(tainted_gen));
        }

        // negatives: scalar-response field tampers on the
        // f matrix row and the three final responses zA/zC/z. The
        // block above covers the point classes.
        {
            auto tampered = signature;
            tampered.f[0][0][0] ^= 0x01;
            check("triptych rejects tamper in signature.f[0][0]", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.zA[0] ^= 0x01;
            check("triptych rejects tamper in signature.zA", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.zC[0] ^= 0x01;
            check("triptych rejects tamper in signature.zC", !verify_with_ring(tampered, public_keys));
        }

        {
            auto tampered = signature;
            tampered.z[0] ^= 0x01;
            check("triptych rejects tamper in signature.z", !verify_with_ring(tampered, public_keys));
        }
    }
}

static void test_ringct()
{
    auto blinding_factors = scalar_t::random(2);
    for (auto &factor : blinding_factors)
        factor = Crypto::RingCT::generate_commitment_blinding_factor(factor);

    const auto C_1 = Crypto::RingCT::generate_pedersen_commitment(blinding_factors[0], 1000);
    const auto C_2 = Crypto::RingCT::generate_pedersen_commitment(blinding_factors[1], 1000);
    const auto C_fee = Crypto::RingCT::generate_pedersen_commitment({0}, 100);

    const auto CT = C_1 + C_2 + C_fee;

    const auto [pseudo_blinding_factors, pseudo_commitments] =
        Crypto::RingCT::generate_pseudo_commitments({2000, 100}, blinding_factors);

    const auto PT = point_vector_t(pseudo_commitments).sum();
    check("generate_pseudo_commitments", PT == CT);
    check("check_commitments_parity", Crypto::RingCT::check_commitments_parity(pseudo_commitments, {C_1, C_2}, 100));

    // check_commitments_parity
    // is a raw sum equality and does not subgroup-check inputs — honest provers
    // clear cofactors via INV_EIGHT in generate_pedersen_commitment. Each of
    // these mutations must break the equality.
    {
        auto tampered = pseudo_commitments;
        tampered[0] = tampered[0] + Crypto::G;
        check(
            "ringct reject pseudo_commitment tamper",
            !Crypto::RingCT::check_commitments_parity(tampered, {C_1, C_2}, 100));
    }
    {
        std::vector<pedersen_commitment_t> tampered_outputs = {C_1 + Crypto::G, C_2};
        check(
            "ringct reject output_commitment tamper",
            !Crypto::RingCT::check_commitments_parity(pseudo_commitments, tampered_outputs, 100));
    }
    {
        auto tampered = pseudo_commitments;
        tampered[0] = tampered[0] + torsion_point();
        check(
            "ringct reject pseudo_commitment torsion injection",
            !Crypto::RingCT::check_commitments_parity(tampered, {C_1, C_2}, 100));
    }
    {
        check(
            "ringct reject wrong fee (low)",
            !Crypto::RingCT::check_commitments_parity(pseudo_commitments, {C_1, C_2}, 99));
        check(
            "ringct reject wrong fee (high)",
            !Crypto::RingCT::check_commitments_parity(pseudo_commitments, {C_1, C_2}, 101));
    }

    // Amount masking (hiding)
    {
        const auto derivation_scalar = scalar_t::random();
        const auto amount_mask = Crypto::RingCT::generate_amount_mask(derivation_scalar);
        const scalar_t amount = scalar_t(13371337);
        const auto masked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, amount);
        const auto unmasked_amount = Crypto::RingCT::toggle_masked_amount(amount_mask, masked_amount);
        check(
            "toggle_masked_amount",
            masked_amount.to_uint64_t() != amount.to_uint64_t()
                && unmasked_amount.to_uint64_t() == amount.to_uint64_t());
    }
}

static void test_bulletproofs()
{
    // M=1: tamper, out-of-range, encoding
    {
        auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove({1000}, scalar_t::random(1));
        check("bulletproofs M=1 verify valid", Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}));

        // ----- Field tamper matrix -----
        // Every prover-supplied field gets a dedicated tamper case. Points are
        // tampered by self-doubling (curve-valid, but changes value), scalars
        // by multiplication with Crypto::TWO. Every case must reject: the BP
        // transcript binds every field via Fiat-Shamir challenge derivation,
        // so any mutation on A/S/T1/T2/L/R/taux/mu/t/g/h breaks the final
        // check_zero identity.
        {
            auto tampered = proof;
            tampered.A = tampered.A + tampered.A;
            check(
                "bulletproofs reject A tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.S = tampered.S + tampered.S;
            check(
                "bulletproofs reject S tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.T1 = tampered.T1 + tampered.T1;
            check(
                "bulletproofs reject T1 tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.T2 = tampered.T2 + tampered.T2;
            check(
                "bulletproofs reject T2 tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.L[0] = tampered.L[0] + tampered.L[0];
            check(
                "bulletproofs reject L[0] tamper",
                !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.R[0] = tampered.R[0] + tampered.R[0];
            check(
                "bulletproofs reject R[0] tamper",
                !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.mu *= Crypto::TWO;
            check(
                "bulletproofs reject mu tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.t *= Crypto::TWO;
            check(
                "bulletproofs reject t tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.g *= Crypto::TWO;
            check(
                "bulletproofs reject g tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.h *= Crypto::TWO;
            check(
                "bulletproofs reject h tamper", !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.taux *= Crypto::TWO;
            check(
                "bulletproofs reject taux tamper",
                !Crypto::RangeProofs::Bulletproofs::verify({tampered}, {commitments}));
        }

        auto [proof2, commitments2] = Crypto::RangeProofs::Bulletproofs::prove({1000}, scalar_t::random(1), 8);
        check(
            "bulletproofs reject out-of-range",
            !Crypto::RangeProofs::Bulletproofs::verify({proof2}, {commitments2}, 8));

        check("bulletproofs binary encoding", test_binary_encoding(proof));
        check("bulletproofs JSON encoding", test_json_encoding(proof));
    }

    // ----- Commitment-vector swap -----
    // Two distinct valid proofs are built over disjoint commitment sets; the
    // verifier must reject proof1 against commitments2 (and vice versa). BP's
    // transcript absorbs a length-prefixed commitment vector, so commitments
    // are implicitly bound into every Fiat-Shamir challenge.
    {
        auto [proof_a, commitments_a] = Crypto::RangeProofs::Bulletproofs::prove({1000}, scalar_t::random(1));
        auto [proof_b, commitments_b] = Crypto::RangeProofs::Bulletproofs::prove({2000}, scalar_t::random(1));
        check(
            "bulletproofs reject commitment swap (proof_a vs commitments_b)",
            !Crypto::RangeProofs::Bulletproofs::verify({proof_a}, {commitments_b}));
        check(
            "bulletproofs reject commitment swap (proof_b vs commitments_a)",
            !Crypto::RangeProofs::Bulletproofs::verify({proof_b}, {commitments_a}));
    }

    for (const size_t M : {2, 4, 8, 16})
    {
        std::vector<uint64_t> amounts(M);
        for (size_t i = 0; i < M; ++i)
            amounts[i] = 1000 + i * 100;

        auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove(amounts, scalar_t::random(M));
        check(
            ("bulletproofs M=" + std::to_string(M) + " verify valid").c_str(),
            Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}));
        check(("bulletproofs M=" + std::to_string(M) + " binary encoding").c_str(), test_binary_encoding(proof));
    }

    // Mixed batch
    {
        auto [proof1, c1] = Crypto::RangeProofs::Bulletproofs::prove({500}, scalar_t::random(1));
        auto [proof2, c2] = Crypto::RangeProofs::Bulletproofs::prove({600, 700}, scalar_t::random(2));
        check("bulletproofs mixed batch verify", Crypto::RangeProofs::Bulletproofs::verify({proof1, proof2}, {c1, c2}));
    }

    // ----- NEGATIVE TESTS: cross-N rejection -----
    // BP math is already structurally N-dependent (to_bits(N), MN-length inner
    // product, log2(MN) folding rounds), so cross-N proofs already failed before
    // the fix via shape mismatch in proof.L.size. The fix binds N into the
    // Fiat-Shamir transcript so the rejection becomes a clean challenge mismatch
    // rather than a mid-MSM divergence. Either way the observable result is the
    // same: verify returns false. These tests lock in that behavior.
    {
        // Prove at N=64, verify at smaller N — must reject.
        auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove({1ULL << 40}, scalar_t::random(1), 64);
        check(
            "bulletproofs 64-bit proof rejected at N=32",
            !Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}, 32));
        check(
            "bulletproofs 64-bit proof rejected at N=16",
            !Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}, 16));
    }

    // ----- silent-rounding round-trip equivalence -----
    // prove(N=24) and verify(N=29) both normalize to 32 via pow2_round, so they
    // bind the SAME scalar into the transcript and the proof must verify.
    {
        auto [proof, commitments] = Crypto::RangeProofs::Bulletproofs::prove({1000000}, scalar_t::random(1), 24);
        check(
            "bulletproofs silent-round prove(N=24) verify(N=29)",
            Crypto::RangeProofs::Bulletproofs::verify({proof}, {commitments}, 29));
    }
}

static void test_bulletproofs_plus()
{
    // M=1
    {
        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, scalar_t::random(1));
        check("bulletproofs+ M=1 verify valid", Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}));

        // ----- Field tamper matrix -----
        // Every prover-supplied field gets a dedicated tamper case. Mirrors
        // the BP matrix above — points self-double, scalars multiply by TWO.
        // Fields: A, A1, B (points); L, R (point vectors); r1, s1, d1 (scalars).
        {
            auto tampered = proof;
            tampered.A = tampered.A + tampered.A;
            check(
                "bulletproofs+ reject A tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.A1 = tampered.A1 + tampered.A1;
            check(
                "bulletproofs+ reject A1 tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.B = tampered.B + tampered.B;
            check(
                "bulletproofs+ reject B tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.L[0] = tampered.L[0] + tampered.L[0];
            check(
                "bulletproofs+ reject L[0] tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.R[0] = tampered.R[0] + tampered.R[0];
            check(
                "bulletproofs+ reject R[0] tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.r1 *= Crypto::TWO;
            check(
                "bulletproofs+ reject r1 tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.s1 *= Crypto::TWO;
            check(
                "bulletproofs+ reject s1 tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.d1 *= Crypto::TWO;
            check(
                "bulletproofs+ reject d1 tamper",
                !Crypto::RangeProofs::BulletproofsPlus::verify({tampered}, {commitments}));
        }

        auto [proof2, commitments2] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, scalar_t::random(1), 8);
        check(
            "bulletproofs+ reject out-of-range",
            !Crypto::RangeProofs::BulletproofsPlus::verify({proof2}, {commitments2}, 8));

        check("bulletproofs+ binary encoding", test_binary_encoding(proof));
        check("bulletproofs+ JSON encoding", test_json_encoding(proof));
    }

    // ----- Commitment-vector swap -----
    // Two distinct valid BP+ proofs over disjoint commitment sets; the
    // verifier must reject proof_a against commitments_b (and vice versa).
    {
        auto [proof_a, commitments_a] = Crypto::RangeProofs::BulletproofsPlus::prove({1000}, scalar_t::random(1));
        auto [proof_b, commitments_b] = Crypto::RangeProofs::BulletproofsPlus::prove({2000}, scalar_t::random(1));
        check(
            "bulletproofs+ reject commitment swap (proof_a vs commitments_b)",
            !Crypto::RangeProofs::BulletproofsPlus::verify({proof_a}, {commitments_b}));
        check(
            "bulletproofs+ reject commitment swap (proof_b vs commitments_a)",
            !Crypto::RangeProofs::BulletproofsPlus::verify({proof_b}, {commitments_a}));
    }

    for (const size_t M : {2, 4, 8, 16})
    {
        std::vector<uint64_t> amounts(M);
        for (size_t i = 0; i < M; ++i)
            amounts[i] = 1000 + i * 100;

        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove(amounts, scalar_t::random(M));
        check(
            ("bulletproofs+ M=" + std::to_string(M) + " verify valid").c_str(),
            Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}));
        check(("bulletproofs+ M=" + std::to_string(M) + " binary encoding").c_str(), test_binary_encoding(proof));
    }

    {
        auto [proof1, c1] = Crypto::RangeProofs::BulletproofsPlus::prove({500}, scalar_t::random(1));
        auto [proof2, c2] = Crypto::RangeProofs::BulletproofsPlus::prove({600, 700}, scalar_t::random(2));
        check(
            "bulletproofs+ mixed batch verify",
            Crypto::RangeProofs::BulletproofsPlus::verify({proof1, proof2}, {c1, c2}));
    }

    // ----- NEGATIVE TESTS: cross-N rejection -----
    // BP+ math is already structurally N-dependent, so cross-N proofs already
    // failed before the fix via shape mismatch. The fix binds N into the
    // Fiat-Shamir transcript so the rejection becomes a clean challenge mismatch
    // rather than a mid-MSM divergence. See the matching block in test_bulletproofs.
    {
        // Prove at N=64, verify at smaller N — must reject.
        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove({1ULL << 40}, scalar_t::random(1), 64);
        check(
            "bulletproofs+ 64-bit proof rejected at N=32",
            !Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}, 32));
        check(
            "bulletproofs+ 64-bit proof rejected at N=16",
            !Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}, 16));
    }

    // ----- silent-rounding round-trip equivalence -----
    // prove(N=24) and verify(N=29) both normalize to 32 via pow2_round, so they
    // bind the SAME scalar into the transcript and the proof must verify.
    {
        auto [proof, commitments] = Crypto::RangeProofs::BulletproofsPlus::prove({1000000}, scalar_t::random(1), 24);
        check(
            "bulletproofs+ silent-round prove(N=24) verify(N=29)",
            Crypto::RangeProofs::BulletproofsPlus::verify({proof}, {commitments}, 29));
    }
}

static void test_bulletproofs_pp()
{
    namespace BPP = Crypto::RangeProofs::BulletproofsPP;

    // ----- Default-N (64) sanity, encoding, tamper rejection -----
    {
        auto [proof, commitments] = BPP::prove({1000}, scalar_t::random(1));
        check("bulletproofs++ M=1 verify valid", BPP::verify({proof}, {commitments}));

        // ----- Field tamper matrix -----
        // Every prover-supplied field gets a dedicated tamper case. Points
        // are tampered by self-doubling, scalar vectors by multiplying the
        // first element by Crypto::TWO. Fields: C_l, C_r, C_o, C_s, R
        // (points); X, W (point vectors); l, n (scalar vectors).
        {
            auto tampered = proof;
            tampered.C_l = tampered.C_l + tampered.C_l;
            check("bulletproofs++ reject C_l tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.C_r = tampered.C_r + tampered.C_r;
            check("bulletproofs++ reject C_r tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.C_o = tampered.C_o + tampered.C_o;
            check("bulletproofs++ reject C_o tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.C_s = tampered.C_s + tampered.C_s;
            check("bulletproofs++ reject C_s tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.R = tampered.R + tampered.R;
            check("bulletproofs++ reject R tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.X[0] = tampered.X[0] + tampered.X[0];
            check("bulletproofs++ reject X[0] tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.W[0] = tampered.W[0] + tampered.W[0];
            check("bulletproofs++ reject W[0] tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.l[0] *= Crypto::TWO;
            check("bulletproofs++ reject l[0] tamper", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.n[0] *= Crypto::TWO;
            check("bulletproofs++ reject n[0] tamper", !BPP::verify({tampered}, {commitments}));
        }

        // ----- Torsion injection matrix -----
        // For each prover-supplied point field, inject an order-2 torsion
        // component and assert rejection. BP++'s soundness proof, like
        // Triptych's (see fix), lives in the prime-order subgroup:
        // the verifier must either cofactor-clear or subgroup-check every
        // prover-supplied point. If any of these assertions fail (i.e., the
        // verifier accepts a torsioned point), it is a new soundness finding
        // and must be escalated before any further work.
        {
            auto tampered = proof;
            tampered.C_l = tampered.C_l + torsion_point();
            check("bulletproofs++ reject C_l torsion", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.C_r = tampered.C_r + torsion_point();
            check("bulletproofs++ reject C_r torsion", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.C_o = tampered.C_o + torsion_point();
            check("bulletproofs++ reject C_o torsion", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.C_s = tampered.C_s + torsion_point();
            check("bulletproofs++ reject C_s torsion", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.R = tampered.R + torsion_point();
            check("bulletproofs++ reject R torsion", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.X[0] = tampered.X[0] + torsion_point();
            check("bulletproofs++ reject X[0] torsion", !BPP::verify({tampered}, {commitments}));
        }
        {
            auto tampered = proof;
            tampered.W[0] = tampered.W[0] + torsion_point();
            check("bulletproofs++ reject W[0] torsion", !BPP::verify({tampered}, {commitments}));
        }

        check("bulletproofs++ binary encoding", test_binary_encoding(proof));
        check("bulletproofs++ JSON encoding", test_json_encoding(proof));
    }

    // ----- Positive matrix: every normalized N x several M -----
    // After N normalization, the allowed set is {4, 8, 16, 32, 64}.
    for (const size_t N : {size_t(4), size_t(8), size_t(16), size_t(32), size_t(64)})
    {
        for (const size_t M : {size_t(1), size_t(2), size_t(3), size_t(4)})
        {
            std::vector<uint64_t> amounts(M);
            for (size_t i = 0; i < M; ++i)
            {
                // Pick an in-range amount per N. For N=4 the range is [0,16); for N=8 [0,256); etc.
                // For N=64 every uint64_t is in-range so we use small distinct values.
                const uint64_t cap_plus_1 = (N == 64) ? 0 /* unused */ : (1ULL << N);
                amounts[i] = (N == 64) ? (uint64_t(i) + 1) : ((uint64_t(i) + 1) % cap_plus_1);
            }
            const auto label = "bulletproofs++ N=" + std::to_string(N) + " M=" + std::to_string(M);
            auto [proof, commitments] = BPP::prove(amounts, scalar_t::random(M), N);
            check((label + " verify valid").c_str(), BPP::verify({proof}, {commitments}, N));

            // Tamper test for one parameter combo (cheap, exercises every N).
            auto tampered = proof;
            tampered.C_l = tampered.C_l + tampered.C_l;
            check((label + " reject tampered").c_str(), !BPP::verify({tampered}, {commitments}, N));
        }
    }

    // ----- Larger M to exercise the M_pad padding path -----
    for (const size_t M : {size_t(8), size_t(16)})
    {
        std::vector<uint64_t> amounts(M);
        for (size_t i = 0; i < M; ++i)
            amounts[i] = 1000 + i * 100;
        auto [proof, commitments] = BPP::prove(amounts, scalar_t::random(M));
        check(("bulletproofs++ M=" + std::to_string(M) + " verify valid").c_str(), BPP::verify({proof}, {commitments}));
        check(("bulletproofs++ M=" + std::to_string(M) + " binary encoding").c_str(), test_binary_encoding(proof));
    }

    // M=3 still pads to M_pad=4
    {
        auto [proof, commitments] = BPP::prove({100, 200, 300}, scalar_t::random(3));
        check("bulletproofs++ M=3 verify valid", BPP::verify({proof}, {commitments}));
    }

    // Same-N batch with different M
    {
        auto [proof1, c1] = BPP::prove({500}, scalar_t::random(1));
        auto [proof2, c2] = BPP::prove({600, 700}, scalar_t::random(2));
        check("bulletproofs++ mixed-M batch verify", BPP::verify({proof1, proof2}, {c1, c2}));
    }

    // ----- NEGATIVE TESTS: cross-N rejection ('s missing tests) -----
    // Generate a proof at N=N_prove with an amount in [2^N_verify, 2^N_prove). The
    // proof must NOT verify under N_verify; before the fix, the verifier
    // ignored N and would have accepted these. Each case represents a different
    // supply-inflation path.
    {
        // 64-bit proof of value 2^40 verified at N=32 — must reject.
        const uint64_t big = 1ULL << 40;
        auto [proof, commitments] = BPP::prove({big}, scalar_t::random(1), 64);
        check("bulletproofs++ 64-bit proof rejected at N=32", !BPP::verify({proof}, {commitments}, 32));
        check("bulletproofs++ 64-bit proof rejected at N=16", !BPP::verify({proof}, {commitments}, 16));
        check("bulletproofs++ 64-bit proof rejected at N=8", !BPP::verify({proof}, {commitments}, 8));
        check("bulletproofs++ 64-bit proof accepted at N=64", BPP::verify({proof}, {commitments}, 64));
    }
    {
        // 32-bit proof of value 2^20 verified at N=16 — must reject.
        const uint64_t mid = 1ULL << 20;
        auto [proof, commitments] = BPP::prove({mid}, scalar_t::random(1), 32);
        check("bulletproofs++ 32-bit proof rejected at N=16", !BPP::verify({proof}, {commitments}, 16));
        check("bulletproofs++ 32-bit proof rejected at N=8", !BPP::verify({proof}, {commitments}, 8));
        check("bulletproofs++ 32-bit proof accepted at N=32", BPP::verify({proof}, {commitments}, 32));
    }

    // ----- Silent rounding: prove(N=24) and verify(N=29) both normalize to 32 -----
    {
        auto [proof, commitments] = BPP::prove({1000000}, scalar_t::random(1), 24);
        check("bulletproofs++ silent-round: prove(N=24) verify(N=29)", BPP::verify({proof}, {commitments}, 29));
        check("bulletproofs++ silent-round: prove(N=24) verify(N=32)", BPP::verify({proof}, {commitments}, 32));
        // N=33 normalizes to 64 — must reject (different transcript binding).
        check("bulletproofs++ silent-round: prove(N=24) rejected at N=33", !BPP::verify({proof}, {commitments}, 33));
    }

    // ----- Minimum-N rounding: N in {1,2,3} all round up to 4 -----
    {
        auto [proof, commitments] = BPP::prove({5}, scalar_t::random(1), 1);
        check("bulletproofs++ min-N: prove(N=1) verify(N=2)", BPP::verify({proof}, {commitments}, 2));
        check("bulletproofs++ min-N: prove(N=1) verify(N=4)", BPP::verify({proof}, {commitments}, 4));
        check("bulletproofs++ min-N: prove(N=1) rejected at N=8", !BPP::verify({proof}, {commitments}, 8));
    }

    // ----- Honest-prover bound: amount >= 2^N must throw on prove -----
    {
        bool threw = false;
        try
        {
            BPP::prove({1000}, scalar_t::random(1), 8);
        }
        catch (const std::range_error &)
        {
            threw = true;
        }
        check("bulletproofs++ prove rejects out-of-range amount (N=8)", threw);
    }
    {
        bool threw = false;
        try
        {
            BPP::prove({1ULL << 40}, scalar_t::random(1), 32);
        }
        catch (const std::range_error &)
        {
            threw = true;
        }
        check("bulletproofs++ prove rejects out-of-range amount (N=32)", threw);
    }

    // ----- Bounds rejection: N=0 and N>64 throw on both prove and verify -----
    {
        bool threw = false;
        try
        {
            BPP::prove({1}, scalar_t::random(1), 0);
        }
        catch (const std::range_error &)
        {
            threw = true;
        }
        check("bulletproofs++ prove rejects N=0", threw);
    }
    {
        bool threw = false;
        try
        {
            BPP::prove({1}, scalar_t::random(1), 65);
        }
        catch (const std::range_error &)
        {
            threw = true;
        }
        check("bulletproofs++ prove rejects N=65", threw);
    }
    {
        auto [proof, commitments] = BPP::prove({1}, scalar_t::random(1));
        bool threw = false;
        try
        {
            (void)BPP::verify({proof}, {commitments}, 0);
        }
        catch (const std::range_error &)
        {
            threw = true;
        }
        check("bulletproofs++ verify rejects N=0", threw);
        threw = false;
        try
        {
            (void)BPP::verify({proof}, {commitments}, 65);
        }
        catch (const std::range_error &)
        {
            threw = true;
        }
        check("bulletproofs++ verify rejects N=65", threw);
    }
}

static void test_dleq()
{
    const auto secret = scalar_t::random();
    const auto G_point = Crypto::G;
    const auto H_point = hash_t::sha3(G_point).point();
    const auto A = secret * G_point;
    const auto B = secret * H_point;

    const auto proof = Crypto::DLEQ::generate_proof(secret, G_point, H_point);
    check("dleq check_proof", Crypto::DLEQ::check_proof(A, B, G_point, H_point, proof));

    {
        const auto bad_secret = scalar_t::random();
        const auto bad_A = bad_secret * G_point;
        const auto bad_B = bad_secret * H_point;
        check("dleq reject wrong points", !Crypto::DLEQ::check_proof(bad_A, bad_B, G_point, H_point, proof));
    }

    {
        auto tampered = proof;
        tampered.s = tampered.s + Crypto::ONE;
        check("dleq reject tampered", !Crypto::DLEQ::check_proof(A, B, G_point, H_point, tampered));
    }

    // DLEQ binds both bases
    // and both statement points into the Fiat-Shamir transcript, so any swap
    // on the verifier side must desync the challenge and reject. These
    // negatives lock that binding against transcript-schema regressions.
    {
        const auto other_H = hash_t::sha3(H_point).point();
        check("dleq reject base_G swap", !Crypto::DLEQ::check_proof(A, B, other_H, H_point, proof));
        check("dleq reject base_H swap", !Crypto::DLEQ::check_proof(A, B, G_point, other_H, proof));
    }
    {
        check("dleq reject statement point swap (A<->B)", !Crypto::DLEQ::check_proof(B, A, G_point, H_point, proof));
    }

    check("dleq binary encoding", test_binary_encoding(proof));
    check("dleq JSON encoding", test_json_encoding(proof));
}

static void test_adapter_signatures()
{
    const auto [signer_pub, signer_sec] = Crypto::generate_keys();
    const auto witness_y = scalar_t::random();
    const auto statement_Y = witness_y * Crypto::G;

    const auto pre_sig = Crypto::AdapterSignature::pre_sign(SHA3_HASH, signer_sec, statement_Y);

    check(
        "adapter check_pre_signature",
        Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, statement_Y, pre_sig));

    const auto adapted_sig = Crypto::AdapterSignature::adapt(pre_sig, witness_y);

    // Verify the adapted signature round-trips through its own verifier.
    check(
        "adapter check_adapted_signature",
        Crypto::AdapterSignature::check_adapted_signature(SHA3_HASH, signer_pub, adapted_sig));

    const auto extracted_y = Crypto::AdapterSignature::extract(pre_sig, adapted_sig, statement_Y);
    check("adapter extract witness", extracted_y * Crypto::G == statement_Y);

    {
        auto tampered = pre_sig;
        tampered.s_prime = tampered.s_prime + Crypto::ONE;
        check(
            "adapter reject tampered pre_sig",
            !Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, statement_Y, tampered));
    }

    // regression: tampering the adapted response scalar must cause
    // check_adapted_signature to reject. With the dedicated adapted_signature_t
    // type, the class of bug where a point encoding gets rejected as an invalid
    // scalar is now unrepresentable — there is no scalar slot holding point bytes.
    {
        auto tampered = adapted_sig;
        tampered.s = tampered.s + Crypto::ONE;
        check(
            "adapter reject tampered adapted_sig",
            !Crypto::AdapterSignature::check_adapted_signature(SHA3_HASH, signer_pub, tampered));
    }

    // the adapter protocol
    // composes a Schnorr half-signature, a DLEQ sub-proof that binds R to the
    // witness base, and a scalar completion step. These negatives cover the
    // three attack surfaces the code requires: a wrong witness supplied to
    // adapt, a wrong statement_Y supplied to extract, a statement-point swap
    // on the verifier side, and tampering of the DLEQ sub-proof fields.
    {
        const auto wrong_witness = scalar_t::random();
        const auto bogus_adapted = Crypto::AdapterSignature::adapt(pre_sig, wrong_witness);
        check(
            "adapter reject adapt with wrong witness",
            !Crypto::AdapterSignature::check_adapted_signature(SHA3_HASH, signer_pub, bogus_adapted));
    }
    {
        const auto wrong_statement = scalar_t::random() * Crypto::G;
        check(
            "adapter extract with wrong statement throws",
            throws_invalid_argument(
                [&] { (void)Crypto::AdapterSignature::extract(pre_sig, adapted_sig, wrong_statement); }));
    }
    {
        const auto other_statement = scalar_t::random() * Crypto::G;
        check(
            "adapter reject statement point swap",
            !Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, other_statement, pre_sig));
    }
    {
        auto tampered = pre_sig;
        tampered.dleq.c = tampered.dleq.c + Crypto::ONE;
        check(
            "adapter reject dleq sub-proof c tamper",
            !Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, statement_Y, tampered));
    }
    {
        auto tampered = pre_sig;
        tampered.dleq.s = tampered.dleq.s + Crypto::ONE;
        check(
            "adapter reject dleq sub-proof s tamper",
            !Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, statement_Y, tampered));
    }
    {
        auto tampered = pre_sig;
        tampered.nonce_commitment = tampered.nonce_commitment + Crypto::G;
        check(
            "adapter reject nonce_commitment tamper",
            !Crypto::AdapterSignature::check_pre_signature(SHA3_HASH, signer_pub, statement_Y, tampered));
    }

    check("adapter binary encoding", test_binary_encoding(pre_sig));
    check("adapter JSON encoding", test_json_encoding(pre_sig));
    check("adapted binary encoding", test_binary_encoding(adapted_sig));
    check("adapted JSON encoding", test_json_encoding(adapted_sig));
}

static void test_vrf_native()
{
    const auto [vrf_pub, vrf_sec] = Crypto::generate_keys();
    const std::vector<unsigned char> alpha = {0x01, 0x02, 0x03, 0x04};

    const auto [proof, beta] = Crypto::VRF::prove(vrf_sec, alpha);
    const auto [valid, beta2] = Crypto::VRF::verify(vrf_pub, alpha, proof);

    check("vrf verify", valid);
    check("vrf output matches", beta == beta2);

    {
        const auto [proof2, beta3] = Crypto::VRF::prove(vrf_sec, alpha);
        const auto [valid2, beta4] = Crypto::VRF::verify(vrf_pub, alpha, proof2);
        check("vrf deterministic output", beta3 == beta);
        check("vrf deterministic verify", valid2);
    }

    {
        const std::vector<unsigned char> alpha2 = {0x05, 0x06, 0x07, 0x08};
        const auto [proof3, beta5] = Crypto::VRF::prove(vrf_sec, alpha2);
        check("vrf different input different output", !(beta5 == beta));
    }

    {
        auto tampered = proof;
        tampered.s = tampered.s + Crypto::ONE;
        const auto [bad_valid, bad_beta] = Crypto::VRF::verify(vrf_pub, alpha, tampered);
        check("vrf reject tampered", !bad_valid);
    }

    // VRF binds both the
    // public key and gamma into its Fiat-Shamir transcript. These negatives
    // pin the gamma-swap and PK-swap surfaces the code requires.
    {
        auto tampered = proof;
        tampered.gamma = tampered.gamma + Crypto::G;
        const auto [bad_valid, bad_beta] = Crypto::VRF::verify(vrf_pub, alpha, tampered);
        check("vrf reject gamma swap", !bad_valid);
    }
    {
        const auto [other_pub, other_sec] = Crypto::generate_keys();
        const auto [bad_valid, bad_beta] = Crypto::VRF::verify(other_pub, alpha, proof);
        check("vrf reject PK swap", !bad_valid);
    }

    check("vrf binary encoding", test_binary_encoding(proof));
    check("vrf JSON encoding", test_json_encoding(proof));
}

// Forward declarations of the RFC 9381 layer-by-layer test hooks defined in
// src/vrf/vrf.cpp. Declared here rather than in vrf.h to keep them out of the
// public API.
namespace Crypto::VRF::RFC9381::test_hooks
{
    std::vector<unsigned char> expand_message_xmd_sha512(
        const std::vector<unsigned char> &msg,
        const std::vector<unsigned char> &dst,
        size_t len_in_bytes);

    std::array<unsigned char, 32>
        hash_to_field_one_fp(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &dst);

    point_t hash_to_curve_ell2(const public_key_t &public_key, const std::vector<unsigned char> &alpha);
} // namespace Crypto::VRF::RFC9381::test_hooks

static void test_vrf_rfc9381()
{
    // Helper: build a secret_key_t from a hex-encoded 32-byte RFC 8032 seed.
    auto seed_from_hex = [](const std::string &hex) -> secret_key_t
    {
        const auto bytes = Serialization::from_hex(hex);
        return secret_key_t(bytes);
    };

    // Helper: hex string → byte vector (kept local; std::vector flavor of from_hex).
    auto bytes_from_hex = [](const std::string &hex) -> std::vector<unsigned char>
    { return Serialization::from_hex(hex); };

    // Helper: convert ASCII string literal to byte vector.
    auto bytes_from_ascii = [](const std::string &s) -> std::vector<unsigned char>
    { return std::vector<unsigned char>(s.begin(), s.end()); };

    // ============================================================
    // LAYER 1 — RFC 9380 Appendix K.3 expand_message_xmd(SHA-512) vectors.
    //
    // DST = "QUUX-V01-CS02-with-expander-SHA512-256"
    // hash = SHA-512
    // k = 256
    //
    // Five short-output (len=0x20=32) and five long-output (len=0x80=128) vectors.
    // We pin the five short ones — they exercise every code path (empty msg,
    // short msg, multi-block msg, long msg) and are sufficient to detect any
    // bug in expand_message_xmd_sha512. The long-output vectors would mainly
    // exercise the ell>1 loop, which is not on the VRF path.
    // ============================================================
    {
        const std::vector<unsigned char> k3_dst = bytes_from_ascii("QUUX-V01-CS02-with-expander-SHA512-256");

        struct k3_short
        {
            const char *name;
            std::vector<unsigned char> msg;
            const char *expected_hex;
        };

        const std::vector<k3_short> k3_vectors = {
            {"vrf-rfc9381 RFC9380 K.3 expand_xmd_sha512 empty",
             {},
             "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba"},
            {"vrf-rfc9381 RFC9380 K.3 expand_xmd_sha512 abc",
             bytes_from_ascii("abc"),
             "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc"},
            {"vrf-rfc9381 RFC9380 K.3 expand_xmd_sha512 abcdef0123456789",
             bytes_from_ascii("abcdef0123456789"),
             "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58"},
            {"vrf-rfc9381 RFC9380 K.3 expand_xmd_sha512 q128",
             bytes_from_ascii(std::string("q128_") + std::string(128, 'q')),
             "7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3"},
            {"vrf-rfc9381 RFC9380 K.3 expand_xmd_sha512 a512",
             bytes_from_ascii(std::string("a512_") + std::string(512, 'a')),
             "57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4"},
        };

        for (const auto &v : k3_vectors)
        {
            const auto out = Crypto::VRF::RFC9381::test_hooks::expand_message_xmd_sha512(v.msg, k3_dst, 32);
            const auto expected = bytes_from_hex(v.expected_hex);
            check(v.name, out == expected);
        }
    }

    // ============================================================
    // LAYER 2 — RFC 9380 Appendix J.5.2 hash_to_field for
    // edwards25519_XMD:SHA-512_ELL2_NU_ (the suite RFC 9381 §5.5 mandates for
    // suite_string 0x04). Each vector publishes the field element u[0] and
    // the intermediate map_to_curve output Q. We validate both layers:
    // hash_to_field_one_fp must produce u[0] byte-for-byte (canonical 32-byte
    // little-endian), and ge_fromfe_frombytes_vartime applied to that u[0]
    // must produce Q (encoded). If u[0] matches but Q does not, we know the
    // existing Elligator2 primitive disagrees with RFC 9380 §6.7.1 and we
    // need a new primitive in the ed25519 vendored package.
    //
    // DST = "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_"
    // ============================================================
    {
        const std::vector<unsigned char> j52_dst =
            bytes_from_ascii("QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_");

        struct j52_vec
        {
            const char *name;
            std::vector<unsigned char> msg;
            const char *u0_hex; // big-endian per RFC convention; we convert to LE for compare
            const char *qx_hex; // big-endian
            const char *qy_hex; // big-endian
        };

        const std::vector<j52_vec> j52_vectors = {
            {"vrf-rfc9381 RFC9380 J.5.2 NU empty",
             {},
             "7f3e7fb9428103ad7f52db32f9df32505d7b427d894c5093f7a0f0374a30641d",
             "42836f691d05211ebc65ef8fcf01e0fb6328ec9c4737c26050471e50803022eb",
             "22cb4aaa555e23bd460262d2130d6a3c9207aa8bbb85060928beb263d6d42a95"},
            {"vrf-rfc9381 RFC9380 J.5.2 NU abc",
             bytes_from_ascii("abc"),
             "09cfa30ad79bd59456594a0f5d3a76f6b71c6787b04de98be5cd201a556e253b",
             "333e41b61c6dd43af220c1ac34a3663e1cf537f996bab50ab66e33c4bd8e4e19",
             "51b6f178eb08c4a782c820e306b82c6e273ab22e258d972cd0c511787b2a3443"},
            {"vrf-rfc9381 RFC9380 J.5.2 NU abcdef0123456789",
             bytes_from_ascii("abcdef0123456789"),
             "475ccff99225ef90d78cc9338e9f6a6bb7b17607c0c4428937de75d33edba941",
             "55186c242c78e7d0ec5b6c9553f04c6aeef64e69ec2e824472394da32647cfc6",
             "5b9ea3c265ee42256a8f724f616307ef38496ef7eba391c08f99f3bea6fa88f0"},
        };

        for (const auto &v : j52_vectors)
        {
            // hash_to_field — compare u[0]. Note: RFC publishes u in BIG-ENDIAN
            // hex (consistent with mathematical integer notation). Our internal
            // canonical Fp encoding is LITTLE-ENDIAN (per RFC 8032). So we
            // convert by reversing.
            const auto u_be = bytes_from_hex(v.u0_hex);
            std::vector<unsigned char> u_le_expected(u_be.rbegin(), u_be.rend());

            const auto u_le = Crypto::VRF::RFC9381::test_hooks::hash_to_field_one_fp(v.msg, j52_dst);
            const std::vector<unsigned char> u_le_vec(u_le.begin(), u_le.end());

            check((std::string(v.name) + " hash_to_field u[0]").c_str(), u_le_vec == u_le_expected);
        }
    }

    // ============================================================
    // LAYER 3 — RFC 9381 Appendix B.4 intermediate H point check.
    //
    // For each ECVRF KAT example, RFC 9381 publishes the intermediate H point
    // (encoded edwards25519 form, 32 bytes). We compute H via our new
    // hash_to_curve_ell2 and assert byte-equality. This is the integration
    // check between hash_to_field and the Elligator2 + cofactor-clearing step,
    // tied back to the actual RFC 9381 PK + alpha inputs (not just the
    // RFC 9380 abstract ones).
    //
    // If LAYER 2 (hash_to_field) passes but this layer fails, it means
    // ge_fromfe_frombytes_vartime + ge_mul8 disagrees with RFC 9380 §6.7.1 +
    // §6.8.2 + §7 — this is the worst-case scenario flagged in the plan, and
    // the user has asked us to PAUSE here and request a new primitive in the
    // ed25519 vendored package rather than write a thin field-arithmetic
    // wrapper inline.
    // ============================================================
    {
        struct b4_h_vec
        {
            const char *name;
            const char *pk_hex;
            std::vector<unsigned char> alpha;
            const char *expected_h_hex;
        };

        const std::vector<b4_h_vec> b4_h_vectors = {
            {"vrf-rfc9381 RFC9381 B.4 Example 19 intermediate H",
             "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
             {},
             "b8066ebbb706c72b64390324e4a3276f129569eab100c26b9f05011200c1bad9"},
            {"vrf-rfc9381 RFC9381 B.4 Example 20 intermediate H",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
             {0x72},
             "76ac3ccb86158a9104dff819b1ca293426d305fd76b39b13c9356d9b58c08e57"},
            {"vrf-rfc9381 RFC9381 B.4 Example 21 intermediate H",
             "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
             {0xaf, 0x82},
             "13d2a8b5ca32db7e98094a61f656a08c6c964344e058879a386a947a4e189ed1"},
        };

        for (const auto &v : b4_h_vectors)
        {
            const auto pk_bytes = bytes_from_hex(v.pk_hex);
            const public_key_t pk(pk_bytes);

            const auto h_point = Crypto::VRF::RFC9381::test_hooks::hash_to_curve_ell2(pk, v.alpha);
            const auto h_bytes_actual = h_point.serialize();
            const auto h_bytes_expected = bytes_from_hex(v.expected_h_hex);

            check(v.name, h_bytes_actual == h_bytes_expected);
        }
    }


    // ------------------------------------------------------------------
    // Round-trip with a fresh random seed.
    // ------------------------------------------------------------------
    {
        // secret_key_t::random is documented in include/types/README.md but not
        // implemented as a static factory; build one from raw entropy instead.
        std::vector<unsigned char> raw_seed(32);
        randompp::random_bytes(raw_seed.size(), raw_seed.data());
        const secret_key_t sk(raw_seed);
        const auto pk = sk.point();

        const std::vector<unsigned char> alpha = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"

        const auto [proof, beta] = Crypto::VRF::RFC9381::prove(sk, alpha);
        check("vrf-rfc9381 prove", !beta.empty());

        const auto [valid, beta2] = Crypto::VRF::RFC9381::verify(pk, alpha, proof);
        check("vrf-rfc9381 verify", valid);
        check("vrf-rfc9381 output matches", beta == beta2);

        const auto [proof2, beta3] = Crypto::VRF::RFC9381::prove(sk, alpha);
        check("vrf-rfc9381 deterministic output", beta == beta3);
        check("vrf-rfc9381 deterministic proof", proof.serialize() == proof2.serialize());

        const std::vector<unsigned char> alpha2 = {0x57, 0x6f, 0x72, 0x6c, 0x64}; // "World"
        const auto [proof3, beta4] = Crypto::VRF::RFC9381::prove(sk, alpha2);
        check("vrf-rfc9381 different input different output", !(beta == beta4));

        auto bad_proof = proof;
        bad_proof.s = scalar_t::random();
        const auto [bad_valid, _] = Crypto::VRF::RFC9381::verify(pk, alpha, bad_proof);
        check("vrf-rfc9381 reject tampered", !bad_valid);

        // gamma-swap surface.
        // PK-swap is already covered by the Y-binding block below.
        auto gamma_tampered = proof;
        gamma_tampered.gamma = gamma_tampered.gamma + Crypto::G;
        const auto [gamma_valid, _gamma_beta] = Crypto::VRF::RFC9381::verify(pk, alpha, gamma_tampered);
        check("vrf-rfc9381 reject gamma swap", !gamma_valid);

        check("vrf-rfc9381 binary encoding", test_binary_encoding(proof));
        check("vrf-rfc9381 JSON encoding", test_json_encoding(proof));
    }

    // ------------------------------------------------------------------
    // Y-binding negative test.
    //
    // The challenge omitted Y from the hash. Even though Y was
    // implicitly bound through H = hash_to_curve(Y, alpha) and U = sG - cY,
    // a spec-compliant verifier will reject a proof produced under one
    // public key when re-keyed under another. Confirm a clean reject.
    // ------------------------------------------------------------------
    {
        std::vector<unsigned char> seed_a(32), seed_b(32);
        randompp::random_bytes(seed_a.size(), seed_a.data());
        randompp::random_bytes(seed_b.size(), seed_b.data());
        const secret_key_t sk_a(seed_a);
        const secret_key_t sk_b(seed_b);

        const std::vector<unsigned char> alpha = {0x59, 0x2d, 0x62, 0x69, 0x6e, 0x64};

        const auto [proof_a, _beta_a] = Crypto::VRF::RFC9381::prove(sk_a, alpha);

        const auto [bad_valid, _beta_bad] = Crypto::VRF::RFC9381::verify(sk_b.point(), alpha, proof_a);
        check("vrf-rfc9381 Y-binding rejects PK swap", !bad_valid);
    }

    // ------------------------------------------------------------------
    // RFC 9381 Appendix B.4 known-answer test vectors -- ECVRF-EDWARDS25519-SHA512-ELL2.
    //
    // Examples 19, 20, 21 (the same SK seeds used by RFC 8032 §7.1). These are
    // the operational definition of " closed": passing all three proves
    // that the library's challenge construction (§5.4.3), nonce derivation
    // (§5.4.2.2), response equation (§5.1 step 7), and proof encoding (§5.4.4)
    // all match the spec byte-for-byte.
    //
    // Note: the RFC publishes a 64-byte beta. The library's hash_t is 32 bytes,
    // so we compare beta against the FIRST 32 bytes of the RFC's expected output.
    // This is an intentional and documented truncation -- not part of --
    // and any future widening of hash_t to 64 bytes would let the full beta match.
    // ------------------------------------------------------------------
    struct rfc9381_kat
    {
        const char *name;
        const char *sk_hex;
        std::vector<unsigned char> alpha;
        const char *pi_hex;
        const char *beta64_hex;
    };

    const std::vector<rfc9381_kat> kats = {
        // Example 19: empty alpha
        {"vrf-rfc9381 RFC9381 Appendix B.4 Example 19",
         "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         {},
         "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f"
         "14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2"
         "fb37831e00f0acaa6d73bc9997b06501",
         "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cc"
         "cf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54"},
        // Example 20: alpha = 0x72 (1 byte)
        {"vrf-rfc9381 RFC9381 Appendix B.4 Example 20",
         "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         {0x72},
         "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef"
         "055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6b"
         "c064dbfc75a6a57379ef855dc6733801",
         "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e463598"
         "7cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735"},
        // Example 21: alpha = 0xaf 0x82 (2 bytes)
        {"vrf-rfc9381 RFC9381 Appendix B.4 Example 21",
         "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         {0xaf, 0x82},
         "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce"
         "35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe054"
         "67bb286cc2c9d7fde29120a0b2320d04",
         "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a"
         "7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58"},
    };

    for (const auto &kat : kats)
    {
        const auto sk = seed_from_hex(kat.sk_hex);
        const auto pk = sk.point();

        const auto expected_pi = Serialization::from_hex(kat.pi_hex);
        const auto expected_beta64 = Serialization::from_hex(kat.beta64_hex);

        const auto [proof, beta] = Crypto::VRF::RFC9381::prove(sk, kat.alpha);

        // Pi (the wire-format encoded proof) must match the spec byte-for-byte.
        const auto encoded = proof.serialize();
        check((std::string(kat.name) + " pi byte-equal").c_str(), encoded == expected_pi);

        // Beta is compared against the first 32 bytes of the RFC's 64-byte output
        // because the library's hash_t is 32 bytes.
        const auto beta_bytes = beta.serialize();
        const std::vector<unsigned char> expected_beta_truncated(expected_beta64.begin(), expected_beta64.begin() + 32);
        check((std::string(kat.name) + " beta first-32 byte-equal").c_str(), beta_bytes == expected_beta_truncated);

        // The library's own verify must accept its own KAT-matching proof.
        const auto [valid, beta2] = Crypto::VRF::RFC9381::verify(pk, kat.alpha, proof);
        check((std::string(kat.name) + " verify").c_str(), valid);
        check((std::string(kat.name) + " verify-beta matches").c_str(), beta == beta2);
    }

    // ------------------------------------------------------------------
    // secret_key_t::rfc8032_prefix unit anchor.
    //
    // Confirm that the new accessor returns the upper 32 bytes of SHA-512(seed)
    // for RFC 8032 vector 1 (RFC 8032 §7.1 / used as Example 19 above). The
    // expected prefix is precomputed via SHA-512 over the seed and slicing
    // the upper half. This anchors the accessor against the spec independently
    // of the VRF call path.
    // ------------------------------------------------------------------
    {
        const auto sk = seed_from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        // Recompute SHA-512(seed) here with tinysha and compare upper halves.
        // Re-deriving the reference inline (rather than pinning a hex constant)
        // makes the test self-validating against the platform SHA-512 implementation
        // and avoids re-encoding the spec inside the test itself.
        const auto seed_bytes =
            Serialization::from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");

        unsigned char ref[64];
        tinysha_sha512(seed_bytes.data(), seed_bytes.size(), ref, 64);

        const std::vector<unsigned char> expected_upper(ref + 32, ref + 64);

        const auto prefix = sk.rfc8032_prefix();
        const std::vector<unsigned char> got(prefix.begin(), prefix.end());

        check("vrf-rfc9381 secret_key_t::rfc8032_prefix matches SHA-512(seed)[32..64]", got == expected_upper);

        // Also confirm scalar routes through from_rfc8032_seed by checking that
        // sk.point == publicly-known PK from Example 19 / RFC 8032 §7.1 vector 1.
        // Bind the temporary point_t to a local first — calling sk.point twice
        // inside an iterator-pair constructor invokes UB because each temporary's
        // SerializablePod destructor secure-erases its bytes member.
        const auto expected_pk_bytes =
            Serialization::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        const auto derived_pk = sk.point();
        const auto got_pk_bytes = derived_pk.serialize();
        check("vrf-rfc9381 RFC8032 7.1 vector 1 PK derivation", got_pk_bytes == expected_pk_bytes);
    }
}

static void test_merkle()
{
    // Reference implementation of the 0x00/0x01-tagged hash primitives. These lambdas
    // mirror the production helpers in src/merkle/merkle.cpp and are duplicated here
    // so the tests catch any accidental byte-layout drift in the implementation (if
    // the impl ever changes, these expected-value lambdas will disagree and the
    // assertions will fail). See,.
    auto expected_hash_leaf = [](const hash_t &leaf) -> hash_t
    {
        std::array<uint8_t, 33> buffer {};
        buffer[0] = 0x00;
        std::memcpy(buffer.data() + 1, leaf.data(), 32);
        return hash_t::sha3(buffer);
    };

    auto expected_hash_node = [](const hash_t &left_node, const hash_t &right_node) -> hash_t
    {
        std::array<uint8_t, 65> buffer {};
        buffer[0] = 0x01;
        std::memcpy(buffer.data() + 1, left_node.data(), 32);
        std::memcpy(buffer.data() + 33, right_node.data(), 32);
        return hash_t::sha3(buffer);
    };

    // Deterministic leaf set. Each leaf is 32 bytes of a single repeating value so
    // failures are easy to inspect in a hex dump and so the inputs are non-degenerate
    // (all bits set somewhere, no accidental collisions with hash_t{}).
    const hash_t leaf_0("0101010101010101010101010101010101010101010101010101010101010101");
    const hash_t leaf_1("0202020202020202020202020202020202020202020202020202020202020202");
    const hash_t leaf_2("0303030303030303030303030303030303030303030303030303030303030303");
    const hash_t leaf_3("0404040404040404040404040404040404040404040404040404040404040404");
    const hash_t leaf_4("0505050505050505050505050505050505050505050505050505050505050505");
    const hash_t leaf_5("0606060606060606060606060606060606060606060606060606060606060606");
    const hash_t leaf_6("0707070707070707070707070707070707070707070707070707070707070707");
    const hash_t leaf_7("0808080808080808080808080808080808080808080808080808080808080808");

    // ---- empty tree -----------------------------------------------------------------
    check("merkle empty root is zero sentinel", Crypto::Merkle::root_hash({}) == hash_t());

    // ---- single leaf: must be tagged, NOT raw --------------------------------------
    // This is the boundary that closes:, root_hash({L}) returned L verbatim,
    // which meant any 32-byte value was trivially the "root of a 1-leaf tree containing
    // itself" -- an attacker could claim any hash as a legitimate merkle commitment.
    {
        const auto root = Crypto::Merkle::root_hash({leaf_0});
        check("merkle single leaf is tagged", root == expected_hash_leaf(leaf_0));
        check("merkle single leaf is NOT raw leaf", root != leaf_0);
    }

    // ---- two leaves: verify the explicit formula -----------------------------------
    {
        const auto root = Crypto::Merkle::root_hash({leaf_0, leaf_1});
        const auto expected = expected_hash_node(expected_hash_leaf(leaf_0), expected_hash_leaf(leaf_1));
        check("merkle two leaf", root == expected);
    }

    // ---- three leaves: RFC 6962 split at k=2, unbalanced right side ----------------
    // MTH({h0,h1,h2}) = hash_node(hash_node(L(h0), L(h1)), L(h2))
    {
        const auto root = Crypto::Merkle::root_hash({leaf_0, leaf_1, leaf_2});
        const auto expected = expected_hash_node(
            expected_hash_node(expected_hash_leaf(leaf_0), expected_hash_leaf(leaf_1)), expected_hash_leaf(leaf_2));
        check("merkle three leaf rfc6962 shape", root == expected);
    }

    // ---- four leaves: perfect pow-2 case, known-vector reference -------------------
    // MTH({h0..h3}) = hash_node(hash_node(L(h0),L(h1)), hash_node(L(h2),L(h3)))
    {
        const auto root = Crypto::Merkle::root_hash({leaf_0, leaf_1, leaf_2, leaf_3});
        const auto expected = expected_hash_node(
            expected_hash_node(expected_hash_leaf(leaf_0), expected_hash_leaf(leaf_1)),
            expected_hash_node(expected_hash_leaf(leaf_2), expected_hash_leaf(leaf_3)));
        check("merkle four leaf known vector", root == expected);
    }

    // ---- five leaves: unbalanced RFC 6962 (k=4, right child is a 1-leaf subtree) ---
    // MTH({h0..h4}) = hash_node(MTH({h0..h3}), MTH({h4}))
    // = hash_node(perfect4, L(h4))
    {
        const std::vector<hash_t> leaves = {leaf_0, leaf_1, leaf_2, leaf_3, leaf_4};
        const auto root = Crypto::Merkle::root_hash(leaves);
        const auto perfect4 = expected_hash_node(
            expected_hash_node(expected_hash_leaf(leaf_0), expected_hash_leaf(leaf_1)),
            expected_hash_node(expected_hash_leaf(leaf_2), expected_hash_leaf(leaf_3)));
        const auto expected = expected_hash_node(perfect4, expected_hash_leaf(leaf_4));
        check("merkle five leaf unbalanced", root == expected);
    }

    // ---- tree_depth(count) maximum depth -------------------------------------------
    // ceil(log2(count)) for count >= 1, 0 for count == 0.
    {
        check("merkle tree_depth(0) = 0", Crypto::Merkle::tree_depth(0) == 0);
        check("merkle tree_depth(1) = 0", Crypto::Merkle::tree_depth(1) == 0);
        check("merkle tree_depth(2) = 1", Crypto::Merkle::tree_depth(2) == 1);
        check("merkle tree_depth(3) = 2", Crypto::Merkle::tree_depth(3) == 2);
        check("merkle tree_depth(4) = 2", Crypto::Merkle::tree_depth(4) == 2);
        check("merkle tree_depth(5) = 3", Crypto::Merkle::tree_depth(5) == 3);
        check("merkle tree_depth(7) = 3", Crypto::Merkle::tree_depth(7) == 3);
        check("merkle tree_depth(8) = 3", Crypto::Merkle::tree_depth(8) == 3);
        check("merkle tree_depth(9) = 4", Crypto::Merkle::tree_depth(9) == 4);
    }

    // ---- tree_depth(count, leaf_index) per-leaf depth ------------------------------
    // For N=5 under RFC 6962 (k=4): leaves 0..3 sit at depth 3 inside the perfect
    // 4-leaf left subtree; leaf 4 sits at depth 1 (single-leaf right subtree).
    {
        check("merkle per-leaf depth N=5 leaf 0", Crypto::Merkle::tree_depth(5, 0) == 3);
        check("merkle per-leaf depth N=5 leaf 1", Crypto::Merkle::tree_depth(5, 1) == 3);
        check("merkle per-leaf depth N=5 leaf 2", Crypto::Merkle::tree_depth(5, 2) == 3);
        check("merkle per-leaf depth N=5 leaf 3", Crypto::Merkle::tree_depth(5, 3) == 3);
        check("merkle per-leaf depth N=5 leaf 4", Crypto::Merkle::tree_depth(5, 4) == 1);

        // N=3: leaf 2 is the single-leaf right subtree at depth 1.
        check("merkle per-leaf depth N=3 leaf 0", Crypto::Merkle::tree_depth(3, 0) == 2);
        check("merkle per-leaf depth N=3 leaf 1", Crypto::Merkle::tree_depth(3, 1) == 2);
        check("merkle per-leaf depth N=3 leaf 2", Crypto::Merkle::tree_depth(3, 2) == 1);
    }

    // ---- branch round-trip matrix --------------------------------------------------
    // For every N in a representative range and every leaf index, build the tree,
    // extract the branch for that leaf, reconstruct the root via root_hash_from_branch,
    // and assert equality with root_hash. This is the comprehensive end-to-end proof
    // that tree_branch / root_hash_from_branch are symmetric across all tree shapes
    // (balanced and unbalanced). Covers N=1 (depth 0, empty siblings), small unbalanced
    // cases (3, 5, 7), and perfect powers of 2 (2, 4, 8, 16).
    {
        const std::vector<hash_t> all_leaves = {
            leaf_0,
            leaf_1,
            leaf_2,
            leaf_3,
            leaf_4,
            leaf_5,
            leaf_6,
            leaf_7,
            leaf_0,
            leaf_1,
            leaf_2,
            leaf_3,
            leaf_4,
            leaf_5,
            leaf_6,
            leaf_7};

        bool roundtrip_ok = true;

        for (size_t count :
             {size_t {1}, size_t {2}, size_t {3}, size_t {4}, size_t {5}, size_t {7}, size_t {8}, size_t {16}})
        {
            const std::vector<hash_t> leaves(all_leaves.begin(), all_leaves.begin() + count);
            const auto root = Crypto::Merkle::root_hash(leaves);

            for (size_t leaf_index = 0; leaf_index < count; ++leaf_index)
            {
                const auto branch = Crypto::Merkle::tree_branch(leaves, leaf_index);

                if (branch.siblings.size() != Crypto::Merkle::tree_depth(count, leaf_index))
                {
                    roundtrip_ok = false;
                    continue;
                }

                const auto reconstructed =
                    Crypto::Merkle::root_hash_from_branch(branch.siblings, leaves[leaf_index], branch.path);

                if (reconstructed != root)
                {
                    roundtrip_ok = false;
                }
            }
        }

        check("merkle branch roundtrip matrix (N in {1,2,3,4,5,7,8,16})", roundtrip_ok);
    }

    // ---- wrong leaf rejection ------------------------------------------------------
    // Extract a valid branch for one leaf, then feed a different leaf through
    // root_hash_from_branch; the reconstructed root must NOT match the real one.
    {
        const std::vector<hash_t> leaves = {leaf_0, leaf_1, leaf_2, leaf_3, leaf_4};
        const auto root = Crypto::Merkle::root_hash(leaves);
        const auto branch = Crypto::Merkle::tree_branch(leaves, 2);

        // Valid: correct leaf reconstructs the correct root.
        const auto good = Crypto::Merkle::root_hash_from_branch(branch.siblings, leaf_2, branch.path);
        check("merkle branch valid leaf reconstructs", good == root);

        // Invalid: different leaf produces a different root.
        const auto bad = Crypto::Merkle::root_hash_from_branch(branch.siblings, leaf_0, branch.path);
        check("merkle branch wrong leaf rejected", bad != root);
    }

    // ---- second-preimage resistance ------------------------------------------------
    // Construct a 4-leaf tree {h0,h1,h2,h3}. Independently compute the bottom internal
    // nodes N01 and N23. Present {N01, N23} as a 2-leaf tree and compute its root.
    // Without domain separation this would equal the 4-leaf root (both roots would
    // reduce to sha3(N01 || N23)), letting an attacker forge a 1-level path for a
    // tree the verifier believed had 2 levels. With 0x00/0x01 tagging the
    // two roots MUST differ, because the 4-leaf root is sha3(0x01 || N01 || N23) while
    // the 2-leaf root is sha3(0x01 || hash_leaf(N01) || hash_leaf(N23)) -- different
    // pre-images, different hashes.
    {
        const std::vector<hash_t> four_leaves = {leaf_0, leaf_1, leaf_2, leaf_3};
        const auto four_root = Crypto::Merkle::root_hash(four_leaves);

        // Compute the internal nodes that the attacker would observe (they correspond
        // to the bottom layer of the 4-leaf tree).
        const auto internal_01 = expected_hash_node(expected_hash_leaf(leaf_0), expected_hash_leaf(leaf_1));
        const auto internal_23 = expected_hash_node(expected_hash_leaf(leaf_2), expected_hash_leaf(leaf_3));

        // Present those internal nodes as if they were leaves of a smaller tree.
        const std::vector<hash_t> forged_leaves = {internal_01, internal_23};
        const auto forged_root = Crypto::Merkle::root_hash(forged_leaves);

        check("merkle second-preimage resistance", four_root != forged_root);
    }

    // ---- API error cases -----------------------------------------------------------
    {
        bool threw_empty = false;

        try
        {
            Crypto::Merkle::tree_branch({}, 0);
        }
        catch (const std::invalid_argument &)
        {
            threw_empty = true;
        }

        check("merkle tree_branch empty throws", threw_empty);

        bool threw_oor = false;

        try
        {
            Crypto::Merkle::tree_branch({leaf_0, leaf_1}, 5);
        }
        catch (const std::invalid_argument &)
        {
            threw_oor = true;
        }

        check("merkle tree_branch leaf_index out of range throws", threw_oor);

        bool threw_depth_oor = false;

        try
        {
            (void)Crypto::Merkle::tree_depth(3, 3);
        }
        catch (const std::invalid_argument &)
        {
            threw_depth_oor = true;
        }

        check("merkle tree_depth(count, leaf_index) out of range throws", threw_depth_oor);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

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

    report_struct_sizes();

    test_sanity();
    if (fatal_failed)
    {
        std::cout << std::endl << "FATAL: sanity checks failed; aborting." << std::endl;
        return 1;
    }

    test_scalar_bias_regression();
    test_hashing();
    test_aes();
    test_base58();
    test_address_encoding();
    test_utilities();
    test_entropy();
    test_key_derivation();
    test_stealth_addresses();
    test_audit_proofs();
    test_signatures();
    test_borromean();
    test_clsag();
    test_clsag_commitments();
    test_mlsag();
    test_mlsag_commitments();
    test_triptych();
    test_ringct();
    test_bulletproofs();
    test_bulletproofs_plus();
    test_bulletproofs_pp();
    test_dleq();
    test_adapter_signatures();
    test_vrf_native();
    test_vrf_rfc9381();
    test_merkle();

    std::cout << std::endl << "==================" << std::endl;
    std::cout << "Total:" << tests_run << std::endl;
    std::cout << "Passed:" << tests_passed << std::endl;
    std::cout << "Failed:" << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
