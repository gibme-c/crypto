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

int main()
{
    std::cout << std::endl << "SLIP-39 Shamir Backup Tests" << std::endl;
    std::cout << "============================" << std::endl;

    // ======================================================================
    // Word list
    // ======================================================================

    std::cout << std::endl << "=== Word List ===" << std::endl;

    {
        const auto words = Crypto::Mnemonics::Shamir::word_list();

        if (!check("wordlist has 1024 words", words.size() == 1024))
            return 1;

        if (!check("wordlist first word is 'academic'", words[0] == "academic"))
            return 1;

        if (!check("wordlist last word is 'zero'", words[1023] == "zero"))
            return 1;
    }

    // ======================================================================
    // Round-trip: 256-bit entropy, 2-of-3
    // ======================================================================

    std::cout << std::endl << "=== Round-trip 256-bit 2-of-3 ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        std::cout << "    entropy: " << entropy << std::endl;

        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);

        if (!check("split produces 3 shares", shares.size() == 3))
            return 1;

        if (!check("shares have 33 words each", shares[0].size() == 33))
            return 1;

        std::cout << "    share 0: ";
        for (size_t i = 0; i < 5; ++i)
            std::cout << shares[0][i] << " ";
        std::cout << "..." << std::endl;

        // Combine shares 0 and 1
        {
            std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
            const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

            if (!check("combine shares 0+1 recovers entropy", recovered == entropy))
                return 1;
        }

        // Combine shares 0 and 2
        {
            std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
            const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

            if (!check("combine shares 0+2 recovers entropy", recovered == entropy))
                return 1;
        }

        // Combine shares 1 and 2
        {
            std::vector<std::vector<std::string>> subset = {shares[1], shares[2]};
            const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

            if (!check("combine shares 1+2 recovers entropy", recovered == entropy))
                return 1;
        }
    }

    // ======================================================================
    // Round-trip: 128-bit entropy, 2-of-3
    // ======================================================================

    std::cout << std::endl << "=== Round-trip 128-bit 2-of-3 ===" << std::endl;

    {
        const auto entropy = entropy_t::random(128, {}, false);

        std::cout << "    entropy: " << entropy << std::endl;

        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);

        if (!check("split produces 3 shares", shares.size() == 3))
            return 1;

        if (!check("128-bit shares have 20 words each", shares[0].size() == 20))
            return 1;

        // Combine any 2 shares
        {
            std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
            const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

            if (!check("128-bit combine recovers entropy", recovered == entropy))
                return 1;
        }
    }

    // ======================================================================
    // Threshold variations: 3-of-5
    // ======================================================================

    std::cout << std::endl << "=== Threshold 3-of-5 ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 3, 5);

        if (!check("split produces 5 shares", shares.size() == 5))
            return 1;

        // 3 shares should succeed
        {
            std::vector<std::vector<std::string>> subset = {shares[0], shares[2], shares[4]};
            const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

            if (!check("3-of-5 with shares 0,2,4 recovers", recovered == entropy))
                return 1;
        }

        // 2 shares should fail (below threshold)
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

            if (!check("2-of-5 fails (below threshold)", threw))
                return 1;
        }
    }

    // ======================================================================
    // Passphrase protection
    // ======================================================================

    std::cout << std::endl << "=== Passphrase ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "test passphrase");

        // Correct passphrase recovers
        {
            std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
            const auto recovered = Crypto::Mnemonics::Shamir::combine(subset, "test passphrase");

            if (!check("correct passphrase recovers entropy", recovered == entropy))
                return 1;
        }

        // Wrong passphrase produces different entropy (plausible deniability by design)
        {
            std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
            const auto wrong_recovered = Crypto::Mnemonics::Shamir::combine(subset, "wrong passphrase");

            if (!check("wrong passphrase produces different entropy", wrong_recovered != entropy))
                return 1;
        }
    }

    // ======================================================================
    // Share validation
    // ======================================================================

    std::cout << std::endl << "=== Share Validation ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);

        if (!check("valid share passes validation", Crypto::Mnemonics::Shamir::validate_share(shares[0])))
            return 1;

        // Corrupt a word
        auto corrupted = shares[0];
        corrupted[5] = (corrupted[5] == "academic") ? "acid" : "academic";

        if (!check("corrupted share fails validation", !Crypto::Mnemonics::Shamir::validate_share(corrupted)))
            return 1;
    }

    // ======================================================================
    // Seed derivation
    // ======================================================================

    std::cout << std::endl << "=== Seed Derivation ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        const auto seed1 = Crypto::Mnemonics::Shamir::derive_seed(entropy, "");
        const auto seed2 = Crypto::Mnemonics::Shamir::derive_seed(entropy, "");

        if (!check("seed derivation is deterministic", seed1 == seed2))
            return 1;

        if (!check("seed is 64 bytes", seed1.size() == 64))
            return 1;

        const auto seed3 = Crypto::Mnemonics::Shamir::derive_seed(entropy, "passphrase");

        if (!check("different passphrase gives different seed", seed1 != seed3))
            return 1;
    }

    // ======================================================================
    // 1-of-1 (threshold=1)
    // ======================================================================

    std::cout << std::endl << "=== 1-of-1 ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 1, 1);

        if (!check("1-of-1 produces 1 share", shares.size() == 1))
            return 1;

        std::vector<std::vector<std::string>> subset = {shares[0]};
        const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

        if (!check("1-of-1 recovers entropy", recovered == entropy))
            return 1;
    }

    // ======================================================================
    // HD key compatibility
    // ======================================================================

    std::cout << std::endl << "=== HD Key Compatibility ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);
        const auto seed_before = seed_t(entropy);
        const auto key_before = seed_before.generate_child_key(44, 0, 0);

        // Split and recombine
        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3);
        std::vector<std::vector<std::string>> subset = {shares[0], shares[2]};
        const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

        const auto seed_after = seed_t(recovered);
        const auto key_after = seed_after.generate_child_key(44, 0, 0);

        const auto [pk_before, sk_before] = key_before.keys();
        const auto [pk_after, sk_after] = key_after.keys();

        if (!check("HD keys match after Shamir round-trip", pk_before == pk_after && sk_before == sk_after))
            return 1;
    }

    // ======================================================================
    // Iteration exponent
    // ======================================================================

    std::cout << std::endl << "=== Iteration Exponent ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        // iteration_exponent = 1 means 5000 iterations per round instead of 2500
        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 1);

        std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
        const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

        if (!check("iteration exponent=1 round-trip", recovered == entropy))
            return 1;
    }

    // ======================================================================
    // Non-extendable mode
    // ======================================================================

    std::cout << std::endl << "=== Non-extendable ===" << std::endl;

    {
        const auto entropy = entropy_t::random(256, {}, false);

        const auto shares = Crypto::Mnemonics::Shamir::split(entropy, 2, 3, "", 0, false);

        std::vector<std::vector<std::string>> subset = {shares[0], shares[1]};
        const auto recovered = Crypto::Mnemonics::Shamir::combine(subset);

        if (!check("non-extendable round-trip", recovered == entropy))
            return 1;

        if (!check("non-extendable share validates", Crypto::Mnemonics::Shamir::validate_share(shares[0])))
            return 1;
    }

    // ======================================================================
    // Summary
    // ======================================================================

    std::cout << std::endl << "============================" << std::endl;
    std::cout << "Total:  " << tests_run << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
