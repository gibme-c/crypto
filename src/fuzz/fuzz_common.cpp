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

#include "fuzz_common.h"

#include <string>
#include <typeinfo>

namespace Crypto
{
    namespace Fuzz
    {
        // -------------------------------------------------------------------
        // bytes_to_hex — fixed-width lowercase hex, truncated at `max_bytes`
        // with a trailing "..." marker when the input is longer. Used by
        // fault reports so a crash log always contains an actionable
        // reproducer blob even when the offending input is a 64 KiB buffer.
        // -------------------------------------------------------------------
        std::string bytes_to_hex(const uint8_t *data, size_t size, size_t max_bytes)
        {
            static const char *hex = "0123456789abcdef";
            const size_t n = (size < max_bytes) ? size : max_bytes;

            std::string out;
            out.reserve(n * 2 + (size > max_bytes ? 3 : 0));
            for (size_t i = 0; i < n; ++i)
            {
                out.push_back(hex[(data[i] >> 4) & 0x0F]);
                out.push_back(hex[data[i] & 0x0F]);
            }
            if (size > max_bytes)
            {
                out.append("...");
            }
            return out;
        }

        // -------------------------------------------------------------------
        // run_fuzz_one_safely — the single point where every fuzz_one
        // invocation is wrapped. The SAFE exception set here defines what
        // the library's malformed-input contract is ALLOWED to throw. Any
        // other exception type is a fault and will be reported as such.
        //
        // SAFE set:
        //   - invalid_argument : library + external malformed-input
        //                        contract (canonical type)
        //   - out_of_range     : library documented index/key OOR contract
        //   - length_error     : external serializable_pod size mismatch +
        //                        from_hex odd-length.
        //   - range_error      : external deserializer bounds +
        //                        varint overflow. The library itself has
        //                        zero internal range_error sites, so
        //                        accepting it here does not mask any
        //                        library-internal signal.
        //
        // Any other exception type is a fault. The classifier is kept
        // deliberately strict so a runtime_error leaking out of a crypto
        // verifier, or a new exception type introduced by an upstream
        // change, surfaces immediately rather than silently passing.
        // -------------------------------------------------------------------
        FaultReport
            run_fuzz_one_safely(const char *target_name, FuzzOneFn fn, const uint8_t *data, size_t size) noexcept
        {
            FaultReport r;
            r.faulted = false;
            r.target = target_name != nullptr ? target_name : "(null)";

            // We MUST NOT propagate anything — this is called from both the
            // smoke driver (which wants to keep iterating on benign errors)
            // and LLVMFuzzerTestOneInput (which is noexcept-by-contract).
            // Every catch below is noexcept-safe: it only assigns to r and
            // stringifies pre-constructed data.

            try
            {
                // Defensive null guard — fn should never be null in practice,
                // but a mis-generated stub is cheaper to detect than debug.
                if (fn == nullptr)
                {
                    r.faulted = true;
                    r.exception_type = "null-function-pointer";
                    r.what_message = "fuzz_one fn was nullptr";
                    return r;
                }
                fn(data, size);
                return r;
            }
            // -- SAFE exceptions: documented malformed-input contract --
            catch (const std::invalid_argument &e)
            {
                // expected; not a fault
                (void)e;
                return r;
            }
            catch (const std::out_of_range &e)
            {
                (void)e;
                return r;
            }
            catch (const std::length_error &e)
            {
                // serializationcpp POD size mismatch / from_hex odd-length
                (void)e;
                return r;
            }
            catch (const std::range_error &e)
            {
                // serializationcpp deserializer bounds / varint overflow
                (void)e;
                return r;
            }
            // -- UNEXPECTED exceptions: fault --
            catch (const std::exception &e)
            {
                r.faulted = true;
                // typeid().name() is ABI-mangled on GCC/Clang; that's fine for
                // escalation purposes — a human triages the report and the
                // mangled name narrows the throw-site faster than a generic
                // "std::exception" would.
                try
                {
                    r.exception_type = typeid(e).name();
                    r.what_message = e.what();
                }
                catch (...)
                {
                    r.exception_type = "std::exception";
                    r.what_message = "(what() itself threw)";
                }
                return r;
            }
            catch (...)
            {
                r.faulted = true;
                r.exception_type = "non-std-exception";
                r.what_message = "caught (...) — likely foreign exception or noexcept violation";
                return r;
            }
        }
    } // namespace Fuzz
} // namespace Crypto
