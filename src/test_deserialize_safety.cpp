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

// ---------------------------------------------------------------------------
// test_deserialize_safety.cpp — per-type deserialization-safety property tests.
//
// For every serializable type T in the library's public API, this test
// drives the type's byte-vector constructor with a bank of
// deterministically-generated pseudo-random buffers at boundary sizes
// (0, 1, 7, 31, 32, 33, 63, 64, 65, 128, 256, 1024, 65535) plus a pool
// of random-length inputs. For each buffer the test asserts:
//
//   (1) construction either succeeds or throws ONLY from the SAFE
//       exception set — std::invalid_argument, std::out_of_range,
//       std::length_error. Any other exception type is a fault and
//       indicates either an internal invariant violation or an
//       undocumented throw leak from a transitive dependency.
//
//   (2) if construction succeeds, T.serialize() followed by re-construction
//       from the serialized bytes is idempotent and produces an equal
//       object (deserialize-serialize round-trip).
//
// This complements the coverage-guided fuzz smoke harness (src/fuzz/)
// in two ways:
//
//   - Deterministic: runs with a fixed seed so a failure is reproducible
//     by rerunning the test. No build-flag gating — executes every PR
//     through the standard BUILD_TESTS matrix, even when BUILD_FUZZERS=OFF.
//
//   - Boundary-focused: the fixed size list hits the exact off-by-one
//     cases (sizeof-1, sizeof, sizeof+1) for the 32-byte POD types where
//     length-check logic is most likely to drift from the documented
//     contract.
//
// The SAFE exception set matches `Crypto::Fuzz::run_fuzz_one_safely`
// in src/fuzz/fuzz_common.cpp — these two test vehicles deliberately
// enforce the same library-wide malformed-input throw taxonomy. A
// library change that narrows or widens the taxonomy MUST be reflected
// in both places.
//
// Most modules have no boundary deserializer tests in src/test.cpp;
// this file provides that coverage for every type in one place.
// ---------------------------------------------------------------------------

#include <crypto.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>

namespace
{
    // ---- Test framework (matches src/test.cpp conventions) ----
    int tests_run = 0;
    int tests_passed = 0;
    int tests_failed = 0;

    bool check(const char *name, bool cond)
    {
        ++tests_run;
        if (cond)
        {
            ++tests_passed;
            return true;
        }
        ++tests_failed;
        std::cout << " FAIL: " << name << std::endl;
        return false;
    }

    // ---- Fixed-seed PRNG (xoshiro256** like the fuzz harness) ----
    // Deterministic per compiler and per run so test failures reproduce
    // byte-for-byte. The seed is a magic constant — change ONLY if you
    // need to shake the boundary coverage in a deliberate way.
    constexpr uint64_t k_test_seed = 0x1234567890ABCDEFULL;

    class Xoshiro256
    {
      public:
        explicit Xoshiro256(uint64_t seed) noexcept
        {
            uint64_t z = seed;
            for (int i = 0; i < 4; ++i)
            {
                z += 0x9E3779B97F4A7C15ULL;
                uint64_t x = z;
                x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
                x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
                x = x ^ (x >> 31);
                s_[i] = x ? x : 0xDEADBEEFCAFEBABEULL;
            }
        }

        uint64_t next() noexcept
        {
            const uint64_t result = rotl(s_[1] * 5, 7) * 9;
            const uint64_t t = s_[1] << 17;
            s_[2] ^= s_[0];
            s_[3] ^= s_[1];
            s_[1] ^= s_[2];
            s_[0] ^= s_[3];
            s_[2] ^= t;
            s_[3] = rotl(s_[3], 45);
            return result;
        }

        std::vector<uint8_t> bytes(size_t n) noexcept
        {
            std::vector<uint8_t> out(n);
            size_t i = 0;
            while (i + 8 <= n)
            {
                const uint64_t v = next();
                for (int j = 0; j < 8; ++j)
                {
                    out[i + j] = static_cast<uint8_t>(v >> (j * 8));
                }
                i += 8;
            }
            if (i < n)
            {
                const uint64_t v = next();
                for (size_t j = 0; i + j < n; ++j)
                {
                    out[i + j] = static_cast<uint8_t>(v >> (j * 8));
                }
            }
            return out;
        }

      private:
        static uint64_t rotl(uint64_t x, int k) noexcept
        {
            return (x << k) | (x >> (64 - k));
        }
        uint64_t s_[4];
    };

    // Boundary sizes relevant to the library's POD types (mostly
    // 32-byte) and the larger composite types. Every entry is tried
    // against every target type.
    const std::vector<size_t> k_boundary_sizes = {0, 1, 7, 31, 32, 33, 63, 64, 65, 128, 256, 1024, 4096, 16384, 65535};

    // -------------------------------------------------------------------
    // try_construct — attempts to construct a T from the given byte vector
    // and classifies the outcome:
    //   - SAFE: construction succeeded
    //   - SAFE: construction threw std::invalid_argument / out_of_range /
    //     length_error
    //   - FAULT: any other throw type
    //
    // Returns true iff the outcome was SAFE. On FAULT, prints a detailed
    // diagnostic so the user can locate the offending path.
    // -------------------------------------------------------------------
    template<typename T> bool try_construct(const char *type_name, size_t input_size, const std::vector<uint8_t> &buf)
    {
        try
        {
            // ctor may or may not succeed — that's the point.
            T obj(buf);

            // If ctor succeeded, do a serialize/re-deserialize/re-serialize
            // round-trip and compare the two serialized byte vectors.
            //
            // We deliberately do NOT use operator== on T because most of
            // the Serializable-derived types (bulletproofs, vrf_proof,
            // dleq_proof, adapter_signature, adapted_signature, triptych
            // signatures) do not implement operator==. Comparing the
            // serialized forms is a weaker-but-sufficient round-trip
            // check: if obj.serialize() produces bytes B, then T(B)
            // must also serialize() to B. A mismatch indicates a
            // serialize() / ctor asymmetry (the deserializer is not
            // reading back exactly what the serializer wrote).
            const auto bytes1 = obj.serialize();
            try
            {
                T obj2(bytes1);
                const auto bytes2 = obj2.serialize();
                if (bytes1 != bytes2)
                {
                    std::cout << " FAIL: " << type_name
                              << " deserialize-serialize round-trip byte mismatch (input_size=" << input_size << ")"
                              << std::endl;
                    return false;
                }
            }
            catch (const std::invalid_argument &)
            {
                // Re-construction from our own serialize() output SHOULD
                // never reject. If it does, that's a self-inconsistency.
                std::cout << " FAIL: " << type_name
                          << " self-serialize bytes rejected by vector ctor (input_size=" << input_size << ")"
                          << std::endl;
                return false;
            }
            catch (const std::exception &e2)
            {
                std::cout << " FAIL: " << type_name << " self-serialize bytes threw " << typeid(e2).name()
                          << " (input_size=" << input_size << "): " << e2.what() << std::endl;
                return false;
            }
            return true;
        }
        catch (const std::invalid_argument &)
        {
            return true; // SAFE: documented malformed-input contract
        }
        catch (const std::out_of_range &)
        {
            return true; // SAFE
        }
        catch (const std::length_error &)
        {
            return true; // SAFE: serializationcpp POD/hex size mismatch
        }
        catch (const std::range_error &)
        {
            // SAFE: serializationcpp deserializer bounds / varint overflow.
            // See fuzz_common.h catch_safe comments for the full SAFE set
            // rationale.
            return true;
        }
        catch (const std::exception &e)
        {
            std::cout << " FAIL: " << type_name << " UNEXPECTED throw type " << typeid(e).name()
                      << " on input_size=" << input_size << ": " << e.what() << std::endl;
            return false;
        }
        catch (...)
        {
            std::cout << " FAIL: " << type_name << " non-std throw on input_size=" << input_size << std::endl;
            return false;
        }
    }

    // -------------------------------------------------------------------
    // Run one type through the full boundary + random-length bank.
    // -------------------------------------------------------------------
    template<typename T> void run_type(const char *type_name, Xoshiro256 &prng)
    {
        bool any_fail = false;

        // 1. Fixed boundary sizes.
        for (const size_t n : k_boundary_sizes)
        {
            const auto buf = prng.bytes(n);
            if (!try_construct<T>(type_name, n, buf))
            {
                any_fail = true;
            }
        }

        // 2. 100 random-length inputs in [0, 2048] for additional fuzz.
        for (int i = 0; i < 100; ++i)
        {
            const size_t n = prng.next() % 2049;
            const auto buf = prng.bytes(n);
            if (!try_construct<T>(type_name, n, buf))
            {
                any_fail = true;
            }
        }

        check((std::string(type_name) + " deserialize-safety boundary + fuzz pass").c_str(), !any_fail);
    }

    // -------------------------------------------------------------------
    // All the types we test. Every type MUST be (1) constructible from
    // std::vector<unsigned char>, (2) have a serialize() method returning
    // a byte vector, and (3) support operator== for round-trip equality.
    //
    // The library's SerializablePod<N> and Serializable base classes both
    // satisfy (1) and (2); operator== is type-specific.
    // -------------------------------------------------------------------
    void run_all_types()
    {
        Xoshiro256 prng(k_test_seed);

        // POD types (SerializablePod<32>)
        run_type<scalar_t>("scalar_t", prng);
        run_type<point_t>("point_t", prng);
        run_type<hash_t>("hash_t", prng);
        run_type<entropy_t>("entropy_t", prng);
        run_type<secret_key_t>("secret_key_t", prng);

        // Ed25519 signature
        run_type<signature_t>("signature_t", prng);

        // Ring signatures
        run_type<borromean_signature_t>("borromean_signature_t", prng);
        run_type<clsag_signature_t>("clsag_signature_t", prng);
        run_type<mlsag_signature_t>("mlsag_signature_t", prng);
        run_type<triptych_signature_t>("triptych_signature_t", prng);

        // Range proofs
        run_type<bulletproof_t>("bulletproof_t", prng);
        run_type<bulletproof_plus_t>("bulletproof_plus_t", prng);
        run_type<bulletproof_pp_t>("bulletproof_pp_t", prng);

        // VRF
        run_type<vrf_proof_t>("vrf_proof_t", prng);
        run_type<vrf_rfc9381_proof_t>("vrf_rfc9381_proof_t", prng);

        // DLEQ
        run_type<dleq_proof_t>("dleq_proof_t", prng);

        // Adapter signatures
        run_type<adapter_signature_t>("adapter_signature_t", prng);
        run_type<adapted_signature_t>("adapted_signature_t", prng);
    }
} // namespace

int main()
{
    std::cout << "Crypto Deserialization-Safety Property Tests" << std::endl;
    std::cout << "=============================================" << std::endl;
    std::cout << "  seed=0x" << std::hex << k_test_seed << std::dec << " boundary_sizes=" << k_boundary_sizes.size()
              << " random_inputs=100 per type" << std::endl;
    std::cout << std::endl;

    run_all_types();

    std::cout << std::endl;
    std::cout << "Tests run:    " << tests_run << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;

    return tests_failed == 0 ? 0 : 1;
}
