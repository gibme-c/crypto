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

// SLIP-39 (Shamir Backup) tests, organised function-per-domain to mirror the pattern in
// ../ed25519 and ../ranshaw test suites. Each test function's locals (entropy, share
// vectors) are released on return, keeping peak memory bounded to a single test.

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static bool check(const char *name, bool condition)
{
    ++tests_run;

    if (condition)
    {
        ++tests_passed;
        return true;
    }

    ++tests_failed;
    std::cout << "  FAIL: " << name << std::endl;
    return false;
}

static void test_slip39_word_list()
{
    const auto words = Crypto::Mnemonics::Shamir::word_list();
    check("wordlist has 1024 words", words.size() == 1024);
    check("wordlist first word is 'academic'", !words.empty() && words[0] == "academic");
    check("wordlist last word is 'zero'", words.size() == 1024 && words[1023] == "zero");
}

static void test_slip39_roundtrip_256_2_of_3()
{
    const auto entropy = entropy_t::random(256, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);

    if (!check("256-bit split produces 3 shares", shares.size() == 3))
        return;
    check("256-bit shares have 33 words each", shares[0].size() == 33);

    {
        std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
        check("256-bit combine shares 0+1", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
    }
    {
        std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
        check("256-bit combine shares 0+2", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
    }
    {
        std::vector<std::vector<std::string>> subset = {shares[1], shares[2]};
        check("256-bit combine shares 1+2", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
    }
}

static void test_slip39_roundtrip_128_2_of_3()
{
    const auto entropy = entropy_t::random(128, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);

    if (!check("128-bit split produces 3 shares", shares.size() == 3))
        return;
    check("128-bit shares have 20 words each", shares[0].size() == 20);

    std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
    check("128-bit combine recovers entropy", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
}

static void test_slip39_threshold_3_of_5()
{
    const auto entropy = entropy_t::random(256, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 3, 5);

    if (!check("3-of-5 split produces 5 shares", shares.size() == 5))
        return;

    {
        std::vector<std::vector<std::string>> subset = {shares[0], shares[2], shares[4]};
        check("3-of-5 with shares 0,2,4 recovers", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
    }

    {
        std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
        bool threw = false;
        try
        {
            Crypto::Mnemonics::Shamir::combine(subset);
        }
        catch (const std::invalid_argument &)
        {
            threw = true;
        }
        check("2-of-5 fails (below threshold)", threw);
    }
}

static void test_slip39_passphrase()
{
    const auto entropy = entropy_t::random(256, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "test passphrase");

    {
        std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
        check(
            "correct passphrase recovers entropy",
            Crypto::Mnemonics::Shamir::combine(subset, "test passphrase") == entropy);
    }

    {
        std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
        check(
            "wrong passphrase produces different entropy",
            Crypto::Mnemonics::Shamir::combine(subset, "wrong passphrase") != entropy);
    }
}

static void test_slip39_share_validation()
{
    const auto entropy = entropy_t::random(256, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);

    check("valid share passes validation", Crypto::Mnemonics::Shamir::validate_share(shares[0]));

    auto corrupted = shares[0];
    corrupted[5] = (corrupted[5] == "academic") ? "acid" : "academic";
    check("corrupted share fails validation", !Crypto::Mnemonics::Shamir::validate_share(corrupted));
}

static void test_slip39_seed_derivation()
{
    const auto entropy = entropy_t::random(256, {}, false);

    const auto seed1 = Crypto::Mnemonics::Shamir::derive_seed(entropy, "");
    const auto seed2 = Crypto::Mnemonics::Shamir::derive_seed(entropy, "");
    check("seed derivation is deterministic", seed1 == seed2);
    check("seed is 64 bytes", seed1.size() == 64);

    const auto seed3 = Crypto::Mnemonics::Shamir::derive_seed(entropy, "passphrase");
    check("different passphrase gives different seed", seed1 != seed3);
}

// T<2 must be rejected because a T=1 code path would bypass the HMAC-SHA256
// digest check.
static void test_slip39_rejects_t_equals_one()
{
    const auto entropy = entropy_t::random(256, {}, false);

    {
        bool threw = false;

        try
        {
            (void)Crypto::Mnemonics::Shamir::split(entropy, 1, 1);
        }
        catch (const std::invalid_argument &)
        {
            threw = true;
        }

        check("split(T=1, N=1) rejected", threw);
    }

    {
        bool threw = false;

        try
        {
            (void)Crypto::Mnemonics::Shamir::split(entropy, 1, 3);
        }
        catch (const std::invalid_argument &)
        {
            threw = true;
        }

        check("split(T=1, N=3) rejected", threw);
    }
}

static void test_slip39_hd_key_compat()
{
    const auto entropy = entropy_t::random(256, {}, false);
    const auto seed_before = seed_t(entropy);
    const auto key_before = seed_before.generate_child_key(44, 0, 0);

    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);
    std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
    const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

    const auto seed_after = seed_t(recovered);
    const auto key_after = seed_after.generate_child_key(44, 0, 0);

    const auto [pk_before, sk_before] = key_before.keys();
    const auto [pk_after, sk_after] = key_after.keys();
    check("HD keys match after Shamir round-trip", pk_before == pk_after && sk_before == sk_after);
}

static void test_slip39_iteration_exponent()
{
    // iteration_exponent = 1 means 5000 iterations per round instead of 2500
    const auto entropy = entropy_t::random(256, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 1);

    std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
    check("iteration exponent=1 round-trip", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
}

static void test_slip39_non_extendable()
{
    const auto entropy = entropy_t::random(256, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 0, false);

    std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
    check("non-extendable round-trip", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
    check("non-extendable share validates", Crypto::Mnemonics::Shamir::validate_share(shares[0]));
}

// ----------------------------------------------------------------------------
// entropy_bits override coverage
//
// split() and derive_seed() infer entropy length via entropy_t::bits() and
// expose a symmetric explicit entropy_bits override on both entry points.
// The tests below cover:
//   1. explicit entropy_bits=256 (positive)
//   2. explicit entropy_bits=128 (positive)
//   3. override honors verbatim even when upper 16 bytes are all zero (the
//      escape-hatch scenario: a caller who knows the full 32 bytes are
//      meaningful despite the type convention)
//   4. default derive_seed() matches explicit 128 on 128-bit entropy
//   5. invalid entropy_bits values are rejected on both split() and derive_seed()
// ----------------------------------------------------------------------------

static void test_slip39_explicit_entropy_bits_256()
{
    const auto entropy = entropy_t::random(256, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 0, true, 256);

    if (!check("explicit entropy_bits=256 split produces 3 shares", shares.size() == 3))
        return;
    check("explicit entropy_bits=256 shares have 33 words each", shares[0].size() == 33);

    std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
    check("explicit entropy_bits=256 round-trip", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
}

static void test_slip39_explicit_entropy_bits_128()
{
    const auto entropy = entropy_t::random(128, {}, false);
    const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 0, true, 128);

    if (!check("explicit entropy_bits=128 split produces 3 shares", shares.size() == 3))
        return;
    check("explicit entropy_bits=128 shares have 20 words each", shares[0].size() == 20);

    std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
    check("explicit entropy_bits=128 round-trip", Crypto::Mnemonics::Shamir::combine(subset) == entropy);
}

static void test_slip39_override_honors_zero_upper_half()
{
    // Construct a 32-byte entropy_t whose lower 16 bytes are deterministic non-zero
    // material and whose upper 16 bytes are all zero. Under the default library
    // convention this looks like 128-bit entropy. The escape hatch lets the caller
    // assert "no, treat all 32 bytes as meaningful" by passing entropy_bits=256.
    std::vector<unsigned char> raw(32, 0);
    for (size_t byte_index = 0; byte_index < 16; ++byte_index)
    {
        raw[byte_index] = static_cast<unsigned char>(0xA0 + byte_index);
    }
    const entropy_t zero_upper_entropy(raw);

    // Sanity: the type convention reports this as 128-bit.
    check("zero-upper entropy reports as 128-bit via convention", zero_upper_entropy.is_128_bit());
    check("zero-upper entropy bits() returns 128", zero_upper_entropy.bits() == 128);

    // Split under the default (convention) path: should produce 20-word 128-bit shares.
    const auto shares_default = Crypto::Mnemonics::Shamir::split(zero_upper_entropy, 2, 3);
    check("default split of zero-upper entropy -> 20-word shares", shares_default[0].size() == 20);

    // Split under the explicit override path with entropy_bits=256: should produce
    // 33-word 256-bit shares because the override is honored verbatim.
    const auto shares_override = Crypto::Mnemonics::Shamir::split(zero_upper_entropy, 2, 3, "", 0, true, 256);
    check("override split of zero-upper entropy -> 33-word shares", shares_override[0].size() == 33);

    // Sanity: the two routes produced demonstrably different share shapes.
    check(
        "override and default produce different share word counts",
        shares_default[0].size() != shares_override[0].size());

    // Round-trip via combine on the explicit-override 256-bit path should recover the
    // full 32 bytes (including the zero upper half) because combine always pads to 32.
    std::vector<std::vector<std::string>> subset_override = {shares_override[0], shares_override[1]};
    const auto recovered = Crypto::Mnemonics::Shamir::combine(subset_override);
    check("override 256-bit combine round-trip", recovered == zero_upper_entropy);

    // derive_seed() on a zero-upper entropy: the 128-bit and 256-bit override paths
    // collapse to an IDENTICAL seed. This is a correct cryptographic consequence of
    // HMAC-SHA256 key padding -- PBKDF2 keys shorter than 64 bytes are right-padded
    // with zeros to the SHA-256 block size, so feeding HMAC 16 bytes [x] produces the
    // same prf output as feeding it 32 bytes [x, 0...]. Lock this equivalence in so a
    // future refactor cannot accidentally introduce non-spec domain separation (e.g.,
    // by appending the length to the salt) without this test catching it. Any
    // salt-based domain separation would silently diverge from the SLIP-39 spec and
    // break interop with reference implementations.
    const auto seed_128_zero_upper = Crypto::Mnemonics::Shamir::derive_seed(zero_upper_entropy, "", true, 128);
    const auto seed_256_zero_upper = Crypto::Mnemonics::Shamir::derive_seed(zero_upper_entropy, "", true, 256);
    check(
        "derive_seed zero-upper entropy: 128 and 256 collapse (HMAC key-padding equivalence)",
        seed_128_zero_upper == seed_256_zero_upper);
    check("derive_seed 128-bit path returns 64 bytes", seed_128_zero_upper.size() == 64);
    check("derive_seed 256-bit path returns 64 bytes", seed_256_zero_upper.size() == 64);

    // For a GENUINELY 256-bit entropy (upper half non-zero with overwhelming probability),
    // the override IS observable: passing entropy_bits=128 truncates to the lower 16 bytes
    // and MUST produce a different seed than the default (bits()=256) path. The override
    // parameter exists so this truncation only happens when the caller explicitly asks
    // for it.
    const auto random_256_entropy = entropy_t::random(256, {}, false);
    const auto seed_default_256 = Crypto::Mnemonics::Shamir::derive_seed(random_256_entropy, "");
    const auto seed_override_128 = Crypto::Mnemonics::Shamir::derive_seed(random_256_entropy, "", true, 128);
    check(
        "derive_seed on random 256-bit entropy: override=128 differs from default (truncation observable)",
        seed_default_256 != seed_override_128);
}

static void test_slip39_derive_seed_default_matches_128()
{
    // For a 128-bit entropy_t (upper half zero by construction via random(128)),
    // the default derive_seed() path must agree byte-for-byte with an explicit
    // entropy_bits=128 call. Anchors the default-path semantics.
    const auto entropy = entropy_t::random(128, {}, false);

    const auto seed_default = Crypto::Mnemonics::Shamir::derive_seed(entropy, "");
    const auto seed_explicit = Crypto::Mnemonics::Shamir::derive_seed(entropy, "", true, 128);
    check("derive_seed default matches explicit 128 on 128-bit entropy", seed_default == seed_explicit);

    // And for a 256-bit entropy_t, default must agree with explicit 256.
    const auto entropy256 = entropy_t::random(256, {}, false);
    const auto seed_default256 = Crypto::Mnemonics::Shamir::derive_seed(entropy256, "");
    const auto seed_explicit256 = Crypto::Mnemonics::Shamir::derive_seed(entropy256, "", true, 256);
    check("derive_seed default matches explicit 256 on 256-bit entropy", seed_default256 == seed_explicit256);
}

static void test_slip39_invalid_entropy_bits_rejected()
{
    const auto entropy = entropy_t::random(256, {}, false);

    bool split_threw = false;
    try
    {
        (void)Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 0, true, 64);
    }
    catch (const std::invalid_argument &)
    {
        split_threw = true;
    }
    check("split rejects entropy_bits=64", split_threw);

    bool split_threw_192 = false;
    try
    {
        (void)Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 0, true, 192);
    }
    catch (const std::invalid_argument &)
    {
        split_threw_192 = true;
    }
    check("split rejects entropy_bits=192", split_threw_192);

    bool derive_threw = false;
    try
    {
        (void)Crypto::Mnemonics::Shamir::derive_seed(entropy, "", true, 64);
    }
    catch (const std::invalid_argument &)
    {
        derive_threw = true;
    }
    check("derive_seed rejects entropy_bits=64", derive_threw);

    bool derive_threw_192 = false;
    try
    {
        (void)Crypto::Mnemonics::Shamir::derive_seed(entropy, "", true, 192);
    }
    catch (const std::invalid_argument &)
    {
        derive_threw_192 = true;
    }
    check("derive_seed rejects entropy_bits=192", derive_threw_192);
}

int main()
{
    std::cout << std::endl << "SLIP-39 Shamir Backup Tests" << std::endl;
    std::cout << "============================" << std::endl;

    test_slip39_word_list();
    test_slip39_roundtrip_256_2_of_3();
    test_slip39_roundtrip_128_2_of_3();
    test_slip39_threshold_3_of_5();
    test_slip39_passphrase();
    test_slip39_share_validation();
    test_slip39_seed_derivation();
    test_slip39_rejects_t_equals_one();
    test_slip39_hd_key_compat();
    test_slip39_iteration_exponent();
    test_slip39_non_extendable();

    // entropy_bits override coverage
    test_slip39_explicit_entropy_bits_256();
    test_slip39_explicit_entropy_bits_128();
    test_slip39_override_honors_zero_upper_half();
    test_slip39_derive_seed_default_matches_128();
    test_slip39_invalid_entropy_bits_rejected();

    std::cout << std::endl << "============================" << std::endl;
    std::cout << "Total:  " << tests_run << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
