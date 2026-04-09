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
// generate_seeds.cpp
//
// One-shot dev-time tool that writes a deterministic seed corpus tree under
// src/fuzz/corpus/<target>/seed-NN.bin for every fuzz target. The seeds are
// not "perfect" inputs to the harness byte-consumption contract — they are
// simply non-empty, structured byte streams that give libFuzzer something
// concrete to mutate from on its first run instead of bootstrapping from
// the empty buffer.
//
// Each target gets four seeds:
//   seed-01.bin: 32-byte deterministic pattern (alternating 0x00/0xFF
//                blocks). Catches off-by-one boundary cases in single-
//                element parses.
//   seed-02.bin: 64-byte sequential ramp (0x00..0x3F). Useful for paths
//                that read pairs of 32-byte structures.
//   seed-03.bin: 256-byte xoshiro stream seeded from a target-name hash.
//                Mid-size body for vector / proof / signature shapes.
//   seed-04.bin: 1024-byte xoshiro stream seeded from a different mix.
//                Caps the per-file size at the documented 1 KiB ceiling.
//
// Total: 26 targets * 4 seeds = 104 files, ~33 KiB.
//
// The generator is intentionally library-independent: it does not link
// against crypto-static. Seed contents are byte streams from a stdlib
// PRNG, not library serializations. This keeps the build target trivial,
// removes any cross-platform serialization dependency, and ensures
// regenerating the corpus is a matter of running one binary against an
// empty (or pre-populated) tree without needing the library to build.
//
// Usage (dev-time, idempotent):
//   ./build/fuzz/crypto-fuzz-seed-generator src/fuzz/corpus/
//
// Re-running overwrites every seed file with identical bytes. New
// targets added to CRYPTO_FUZZ_TARGET_LIST should be added to the
// kTargets array below in the same order.
// ---------------------------------------------------------------------------

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    // Mirror of CRYPTO_FUZZ_TARGET_LIST(X) from src/fuzz/fuzz_targets.h.
    // Keep this list in lockstep with that header.
    constexpr const char *kTargets[] = {
        "scalar",    "point",  "hash",      "entropy", "hd_keys", "secret_key", "transcript", "base58", "addresses",
        "mnemonics", "slip39", "signature", "rfc8032", "dleq",    "adapter",    "borromean",  "clsag",  "mlsag",
        "triptych",  "bp",     "bpplus",    "bppp",    "ringct",  "vrf",        "merkle",     "audit",  "aes",
    };

    // xoshiro256** — same family the harness uses internally. Keeping the
    // generator's PRNG identical to the harness's gives libFuzzer seeds
    // whose statistical shape resembles what the smoke driver would
    // naturally produce, even though the actual bytes differ.
    struct Xoshiro256ss
    {
        uint64_t s[4];

        explicit Xoshiro256ss(uint64_t seed)
        {
            // SplitMix64 expansion of the seed into 4 state words.
            uint64_t z = seed + 0x9E3779B97F4A7C15ULL;
            for (int i = 0; i < 4; ++i)
            {
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
                s[i] = z ^ (z >> 31);
                z += 0x9E3779B97F4A7C15ULL;
            }
        }

        static uint64_t rotl(uint64_t x, int k)
        {
            return (x << k) | (x >> (64 - k));
        }

        uint64_t next()
        {
            const uint64_t result = rotl(s[1] * 5, 7) * 9;
            const uint64_t t = s[1] << 17;
            s[2] ^= s[0];
            s[3] ^= s[1];
            s[1] ^= s[2];
            s[0] ^= s[3];
            s[2] ^= t;
            s[3] = rotl(s[3], 45);
            return result;
        }

        void fill(uint8_t *out, size_t n)
        {
            size_t i = 0;
            while (i + 8 <= n)
            {
                uint64_t v = next();
                std::memcpy(out + i, &v, 8);
                i += 8;
            }
            if (i < n)
            {
                uint64_t v = next();
                std::memcpy(out + i, &v, n - i);
            }
        }
    };

    // Simple FNV-1a 64-bit hash of the target name. Stable across compilers.
    uint64_t fnv1a_64(const char *s)
    {
        uint64_t h = 0xCBF29CE484222325ULL;
        while (*s)
        {
            h ^= static_cast<uint8_t>(*s++);
            h *= 0x100000001B3ULL;
        }
        return h;
    }

    bool write_seed(const std::filesystem::path &path, const std::vector<uint8_t> &bytes)
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            std::cerr << "  ! failed to open " << path.string() << " for writing\n";
            return false;
        }
        out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!out)
        {
            std::cerr << "  ! short write to " << path.string() << "\n";
            return false;
        }
        return true;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::cerr << "usage: " << (argv[0] ? argv[0] : "crypto-fuzz-seed-generator") << " <corpus-root-dir>\n";
        return 1;
    }

    const std::filesystem::path root = argv[1];

    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec)
    {
        std::cerr << "failed to create root directory " << root.string() << ": " << ec.message() << "\n";
        return 1;
    }

    size_t total_files = 0;
    size_t total_bytes = 0;

    for (const char *target : kTargets)
    {
        const std::filesystem::path target_dir = root / target;
        std::filesystem::create_directories(target_dir, ec);
        if (ec)
        {
            std::cerr << "failed to create " << target_dir.string() << ": " << ec.message() << "\n";
            return 1;
        }

        const uint64_t mix = fnv1a_64(target);

        // seed-01.bin: 32-byte alternating-block pattern.
        {
            std::vector<uint8_t> bytes(32);
            for (size_t i = 0; i < bytes.size(); ++i)
            {
                bytes[i] = (i & 8) ? 0xFF : 0x00;
            }
            if (!write_seed(target_dir / "seed-01.bin", bytes))
                return 1;
            total_files++;
            total_bytes += bytes.size();
        }

        // seed-02.bin: 64-byte sequential ramp.
        {
            std::vector<uint8_t> bytes(64);
            for (size_t i = 0; i < bytes.size(); ++i)
            {
                bytes[i] = static_cast<uint8_t>(i);
            }
            if (!write_seed(target_dir / "seed-02.bin", bytes))
                return 1;
            total_files++;
            total_bytes += bytes.size();
        }

        // seed-03.bin: 256-byte xoshiro stream seeded from name hash.
        {
            std::vector<uint8_t> bytes(256);
            Xoshiro256ss prng(mix);
            prng.fill(bytes.data(), bytes.size());
            if (!write_seed(target_dir / "seed-03.bin", bytes))
                return 1;
            total_files++;
            total_bytes += bytes.size();
        }

        // seed-04.bin: 1024-byte xoshiro stream from a different mix.
        {
            std::vector<uint8_t> bytes(1024);
            Xoshiro256ss prng(mix ^ 0xA5A5A5A5A5A5A5A5ULL);
            prng.fill(bytes.data(), bytes.size());
            if (!write_seed(target_dir / "seed-04.bin", bytes))
                return 1;
            total_files++;
            total_bytes += bytes.size();
        }
    }

    std::cout << "wrote " << total_files << " seed files (" << total_bytes << " bytes) under " << root.string() << "\n";
    return 0;
}
