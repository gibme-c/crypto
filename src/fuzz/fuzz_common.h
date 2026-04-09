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

#ifndef CRYPTO_FUZZ_COMMON_H
#define CRYPTO_FUZZ_COMMON_H

// ---------------------------------------------------------------------------
// Shared fuzz-harness infrastructure.
//
// Design goals:
//   (1) Every per-module fuzz_target_<mod>.cpp exports a single
//       `void fuzz_one_<mod>(const uint8_t*, size_t) noexcept` entry point.
//       It MUST NOT propagate any exception. It MUST NOT terminate. It MUST
//       NOT write to stdout/stderr on the happy path.
//   (2) Both front-ends (portable smoke driver + libFuzzer stub) call these
//       entries with adversarial bytes. The smoke driver supplies bytes from
//       a deterministic PRNG; libFuzzer supplies its corpus-guided bytes.
//   (3) The ONLY exceptions allowed to escape a fuzz_one body are those
//       listed in SAFE_EXCEPTIONS below (std::invalid_argument, etc.) — these
//       represent the library's documented throw-on-malformed-input contract.
//       Anything else is a fault and must be captured by the safe-exception
//       wrapper for escalation.
//
// Escalation rule: any fault this harness surfaces must be reported for
// triage. No silent fixes.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace Crypto
{
    namespace Fuzz
    {
        // -------------------------------------------------------------------
        // FuzzByteReader — safe bounds-checked byte stream consumer.
        //
        // Per-module fuzz_one bodies use this to slice the libFuzzer-supplied
        // input buffer into the fixed-size pieces they need (32-byte scalars,
        // 32-byte points, variable-length vectors, etc.). Any out-of-bounds
        // read returns a zero-filled buffer rather than throwing — fuzzers
        // hit EOF constantly and we want that to be a "skip this path",
        // not a fault.
        // -------------------------------------------------------------------
        class FuzzByteReader
        {
          public:
            FuzzByteReader(const uint8_t *data, size_t size) noexcept: m_data(data), m_size(size), m_pos(0) {}

            // Remaining bytes in the stream.
            size_t remaining() const noexcept
            {
                return m_size - m_pos;
            }

            // True when the stream is exhausted.
            bool empty() const noexcept
            {
                return m_pos >= m_size;
            }

            // Read exactly N bytes into `out`. If fewer than N remain, the tail
            // is zero-filled and the function returns false. Callers that need
            // "real" bytes can check the return value; callers that only need
            // "some bytes" can ignore it.
            bool read_bytes(uint8_t *out, size_t n) noexcept
            {
                const size_t avail = remaining();
                const size_t take = (avail < n) ? avail : n;
                if (take > 0)
                {
                    std::memcpy(out, m_data + m_pos, take);
                    m_pos += take;
                }
                if (take < n)
                {
                    std::memset(out + take, 0, n - take);
                    return false;
                }
                return true;
            }

            // Convenience: return a std::vector of exactly N bytes (zero-padded
            // if the stream is short).
            std::vector<uint8_t> read_vector(size_t n)
            {
                std::vector<uint8_t> v(n, 0);
                if (n > 0)
                {
                    (void)read_bytes(v.data(), n);
                }
                return v;
            }

            // Read a single byte (0 on EOF).
            uint8_t read_u8() noexcept
            {
                uint8_t b = 0;
                (void)read_bytes(&b, 1);
                return b;
            }

            // Read a single byte and clamp it to [lo, hi]. Used to pick ring
            // sizes, loop bounds, mode selectors without letting the fuzzer
            // pick pathologically-large values. `lo` must be < `hi`; if
            // lo >= hi the function returns lo.
            //
            // Arithmetic is done in uint32_t to avoid a uint8_t wrap at
            // the lo=0, hi=255 boundary (hi-lo+1 = 256 which is 0 mod 256).
            // MSVC flagged the old uint8_t path as C4724 "potential mod by 0"
            // and was correct — that was a latent bug.
            uint8_t read_u8_range(uint8_t lo, uint8_t hi) noexcept
            {
                if (hi <= lo)
                {
                    return lo;
                }
                const uint8_t b = read_u8();
                const uint32_t span = static_cast<uint32_t>(hi) - static_cast<uint32_t>(lo) + 1u;
                return static_cast<uint8_t>(lo + (static_cast<uint32_t>(b) % span));
            }

            // Read a 32-bit little-endian integer (0 on EOF tail).
            uint32_t read_u32_le() noexcept
            {
                uint8_t b[4] = {0, 0, 0, 0};
                (void)read_bytes(b, 4);
                return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8)
                       | (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
            }

          private:
            const uint8_t *m_data;
            size_t m_size;
            size_t m_pos;
        };

        // -------------------------------------------------------------------
        // FuzzPRNG — xoshiro256** deterministic PRNG.
        //
        // Used ONLY by the portable smoke driver, NOT by per-module fuzz_one
        // bodies. The smoke driver synthesizes random byte buffers of varying
        // lengths and feeds them into every fuzz_one_<mod>. libFuzzer does the
        // same job via its own coverage-guided mutator when the Linux+Clang
        // front-end is built.
        //
        // Explicitly deterministic: the same seed always produces the same
        // byte stream. This is how a CI failure reproduces locally. See
        // smoke_main.cpp for how the seed is surfaced on fault.
        // -------------------------------------------------------------------
        class FuzzPRNG
        {
          public:
            explicit FuzzPRNG(uint64_t seed) noexcept
            {
                // SplitMix64 to distribute the single seed across the four
                // state words, avoiding the all-zero absorbing state.
                uint64_t z = seed;
                for (int i = 0; i < 4; ++i)
                {
                    z += 0x9E3779B97F4A7C15ULL;
                    uint64_t x = z;
                    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
                    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
                    x = x ^ (x >> 31);
                    m_s[i] = x ? x : 0xDEADBEEFCAFEBABEULL;
                }
            }

            uint64_t next() noexcept
            {
                const uint64_t result = rotl(m_s[1] * 5, 7) * 9;
                const uint64_t t = m_s[1] << 17;
                m_s[2] ^= m_s[0];
                m_s[3] ^= m_s[1];
                m_s[1] ^= m_s[2];
                m_s[0] ^= m_s[3];
                m_s[2] ^= t;
                m_s[3] = rotl(m_s[3], 45);
                return result;
            }

            void fill(uint8_t *out, size_t n) noexcept
            {
                while (n >= 8)
                {
                    const uint64_t v = next();
                    for (int i = 0; i < 8; ++i)
                    {
                        out[i] = static_cast<uint8_t>(v >> (i * 8));
                    }
                    out += 8;
                    n -= 8;
                }
                if (n > 0)
                {
                    const uint64_t v = next();
                    for (size_t i = 0; i < n; ++i)
                    {
                        out[i] = static_cast<uint8_t>(v >> (i * 8));
                    }
                }
            }

          private:
            static uint64_t rotl(uint64_t x, int k) noexcept
            {
                return (x << k) | (x >> (64 - k));
            }

            uint64_t m_s[4];
        };

        // -------------------------------------------------------------------
        // FaultReport — structured fault captured by the safe-exception
        // wrapper. The portable smoke driver prints this to stderr and exits
        // non-zero on the first fault. libFuzzer's stub doesn't use this —
        // libFuzzer's own crash handler produces the reproducer in its
        // native format.
        // -------------------------------------------------------------------
        struct FaultReport
        {
            bool faulted;
            std::string target; // fuzz target name (e.g. "scalar")
            std::string exception_type; // typeid or synthesized label
            std::string what_message; // exception::what() or synthesized
        };

        // -------------------------------------------------------------------
        // run_fuzz_one_safely — invokes a per-module fuzz_one entry point
        // and catches ALL std::exception + ... escapes. Classifies each
        // escape as either SAFE (documented throw-on-malformed-input) or
        // FAULT (unexpected). Returns a FaultReport with faulted=false on
        // success or on a SAFE catch.
        //
        // SAFE exceptions (expected from the library's malformed-input
        // contract):
        //   - std::invalid_argument
        //   - std::out_of_range
        //   - std::length_error
        //
        // The SAFE set is intentionally tight. It is widened ONLY where a
        // real module has a documented reason to throw a different type —
        // never as a shortcut to silence a surprising throw. A surprise
        // throw is a finding, not a harness-tuning excuse.
        // -------------------------------------------------------------------
        using FuzzOneFn = void (*)(const uint8_t *, size_t);

        FaultReport
            run_fuzz_one_safely(const char *target_name, FuzzOneFn fn, const uint8_t *data, size_t size) noexcept;

        // -------------------------------------------------------------------
        // bytes_to_hex — small helper used by fault reports. Caps at 256
        // bytes to keep log output bounded when a fuzzer dumps a huge input.
        // -------------------------------------------------------------------
        std::string bytes_to_hex(const uint8_t *data, size_t size, size_t max_bytes = 256);

        // -------------------------------------------------------------------
        // catch_safe — run a callable, swallow ONLY the SAFE exception set
        // (invalid_argument / out_of_range / length_error / range_error),
        // and re-throw anything else so the outer run_fuzz_one_safely
        // wrapper classifies it as a fault.
        //
        // Per-module fuzz bodies use this to exercise many library entry
        // points in one iteration. Without it, the first SAFE throw would
        // short-circuit the remaining calls in the body, burning coverage.
        // With it, each call is independent: SAFE throws are benign "input
        // wasn't valid for this path, try the next" events, and unexpected
        // throws still propagate to the outer fault handler.
        //
        // SAFE-set composition:
        //   - invalid_argument : library + external malformed-input
        //                        contract (canonical type)
        //   - out_of_range     : library documented "index/key out of
        //                        range" contract
        //   - length_error     : external serializable_pod size mismatch
        //                        + from_hex odd-length
        //   - range_error      : external deserializer bounds checks
        //                        (underflow/overflow) + varint overflow.
        //                        The library itself has zero internal
        //                        range_error sites, so accepting it here
        //                        does not mask any library-internal signal.
        //
        // The template is header-only and trivially inlinable. It must
        // stay in sync with the SAFE set in run_fuzz_one_safely — any
        // exception class caught here must also be caught there, and
        // vice versa. It must also stay in sync with the SAFE set in
        // src/test_deserialize_safety.cpp::try_construct.
        // -------------------------------------------------------------------
        template<typename F> inline void catch_safe(F &&f)
        {
            try
            {
                f();
            }
            catch (const std::invalid_argument &)
            {
                // expected — library documented malformed-input contract
            }
            catch (const std::out_of_range &)
            {
                // expected — library documented malformed-input contract
            }
            catch (const std::length_error &)
            {
                // expected — serializationcpp POD size mismatch / hex odd-length
            }
            catch (const std::range_error &)
            {
                // expected — serializationcpp deserializer bounds / varint overflow
            }
        }
    } // namespace Fuzz
} // namespace Crypto

#endif // CRYPTO_FUZZ_COMMON_H
