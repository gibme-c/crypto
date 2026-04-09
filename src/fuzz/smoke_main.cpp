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
// smoke_main.cpp — portable fuzz smoke driver.
//
// This binary is the "fuzz on every compiler" half of the dual front-end.
// It compiles on GCC, Clang (LLVM + Apple), MSVC, and MinGW because it
// deliberately avoids any libFuzzer, libfuzzer-sanitizer, or platform-
// specific instrumentation machinery. It uses a deterministic xoshiro256**
// PRNG (see fuzz_common.h) to synthesize random byte buffers of varying
// lengths and feeds them into every registered fuzz_one_<mod> entry point.
//
// Reproducibility: a CI run prints the seed on fault so the same failing
// run can be reproduced locally via:
//   crypto-fuzz-smoke <seed>
//
// Iteration budget:
//   CRYPTO_FUZZ_SMOKE_ITERS    iterations per target  (default  500)
//   CRYPTO_FUZZ_SMOKE_MAX_LEN  max synthesized length (default 4096)
//   CRYPTO_FUZZ_SMOKE_ONLY     restrict to one target by name (unset = all)
//
// The defaults are tuned to keep the total CTest runtime under ~30s on
// every matrix cell. When BUILD_FUZZERS=ON on Linux+Clang the coverage-
// guided libFuzzer harnesses do the deeper exploration work — this driver
// is the always-on regression net, not the primary bug-finder.
//
// Escalation rule (HARD): this driver NEVER attempts to classify a fault
// as "probably fine". If a fuzz_one body throws an exception outside the
// SAFE set, the driver prints the seed + target + exception type + the
// offending byte prefix in hex, and exits non-zero. The user triages.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    struct TargetEntry
    {
        const char *name;
        Crypto::Fuzz::FuzzOneFn fn;
    };

    // Build the target table from the X-macro list. Each entry is a
    // {name, function-pointer} pair.
    const TargetEntry k_targets[] = {
#define X(name_str, fn_sym) {name_str, fn_sym},
        CRYPTO_FUZZ_TARGET_LIST(X)
#undef X
    };

    constexpr size_t k_target_count = sizeof(k_targets) / sizeof(k_targets[0]);

    // Parse a uint64_t from env var or fall back to default. Accepts
    // decimal and 0x-prefixed hex.
    uint64_t parse_env_u64(const char *name, uint64_t fallback)
    {
        const char *s = std::getenv(name);
        if (s == nullptr || *s == '\0')
        {
            return fallback;
        }
        try
        {
            return std::stoull(s, nullptr, 0);
        }
        catch (...)
        {
            return fallback;
        }
    }

    // Parse a seed from argv[1] or synthesize one from the wall clock.
    // Command-line beats env beats clock.
    uint64_t resolve_seed(int argc, char **argv)
    {
        if (argc >= 2 && argv[1] != nullptr && argv[1][0] != '\0')
        {
            try
            {
                return std::stoull(argv[1], nullptr, 0);
            }
            catch (...)
            {
                // Fall through to env/clock.
            }
        }
        const uint64_t env_seed = parse_env_u64("CRYPTO_FUZZ_SMOKE_SEED", 0);
        if (env_seed != 0)
        {
            return env_seed;
        }
        const auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
        const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        return static_cast<uint64_t>(ns);
    }
} // namespace

int main(int argc, char **argv)
{
    const uint64_t seed = resolve_seed(argc, argv);
    const uint64_t iters = parse_env_u64("CRYPTO_FUZZ_SMOKE_ITERS", 500);
    const uint64_t max_len_u = parse_env_u64("CRYPTO_FUZZ_SMOKE_MAX_LEN", 4096);
    const size_t max_len = (max_len_u > 65536) ? 65536 : static_cast<size_t>(max_len_u);
    const char *only = std::getenv("CRYPTO_FUZZ_SMOKE_ONLY");

    std::fprintf(
        stdout,
        "[crypto-fuzz-smoke] seed=0x%016llx iters=%llu max_len=%zu targets=%zu\n",
        static_cast<unsigned long long>(seed),
        static_cast<unsigned long long>(iters),
        max_len,
        k_target_count);
    std::fflush(stdout);

    Crypto::Fuzz::FuzzPRNG prng(seed);
    std::vector<uint8_t> buf(max_len, 0);

    uint64_t total_invocations = 0;
    uint64_t total_skipped = 0;

    for (size_t t = 0; t < k_target_count; ++t)
    {
        const TargetEntry &entry = k_targets[t];

        if (only != nullptr && std::strcmp(only, entry.name) != 0)
        {
            ++total_skipped;
            continue;
        }

        for (uint64_t i = 0; i < iters; ++i)
        {
            // Pick a length in [0, max_len] biased slightly toward short
            // buffers (short inputs hit the boundary-validation paths we
            // care most about).
            const uint64_t r_len = prng.next();
            size_t len;
            if ((r_len & 0xFF) < 16)
            {
                // ~6% chance of a very short input.
                len = static_cast<size_t>((r_len >> 8) % 33);
            }
            else if ((r_len & 0xFF) < 64)
            {
                // ~19% chance of a medium input (<= 256 bytes).
                len = static_cast<size_t>((r_len >> 8) % 257);
            }
            else
            {
                len = static_cast<size_t>((r_len >> 8) % (max_len + 1));
            }

            prng.fill(buf.data(), len);

            const Crypto::Fuzz::FaultReport rep =
                Crypto::Fuzz::run_fuzz_one_safely(entry.name, entry.fn, buf.data(), len);

            ++total_invocations;

            if (rep.faulted)
            {
                std::fprintf(
                    stderr,
                    "\n[crypto-fuzz-smoke] FAULT\n"
                    "  target=%s\n"
                    "  seed=0x%016llx\n"
                    "  iteration=%llu\n"
                    "  length=%zu\n"
                    "  exception_type=%s\n"
                    "  what=%s\n"
                    "  bytes=%s\n"
                    "\n"
                    "Reproduce: crypto-fuzz-smoke 0x%016llx\n"
                    "(with CRYPTO_FUZZ_SMOKE_ONLY=%s CRYPTO_FUZZ_SMOKE_ITERS=%llu)\n",
                    rep.target.c_str(),
                    static_cast<unsigned long long>(seed),
                    static_cast<unsigned long long>(i),
                    len,
                    rep.exception_type.c_str(),
                    rep.what_message.c_str(),
                    Crypto::Fuzz::bytes_to_hex(buf.data(), len).c_str(),
                    static_cast<unsigned long long>(seed),
                    rep.target.c_str(),
                    static_cast<unsigned long long>(iters));
                std::fflush(stderr);
                return 1;
            }
        }
    }

    std::fprintf(
        stdout,
        "[crypto-fuzz-smoke] OK invocations=%llu skipped_targets=%llu\n",
        static_cast<unsigned long long>(total_invocations),
        static_cast<unsigned long long>(total_skipped));
    std::fflush(stdout);
    return 0;
}
