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
// libfuzzer_main.cpp — LLVMFuzzerTestOneInput dispatcher shim.
//
// One libFuzzer binary is built per per-module fuzz target. Each binary
// defines the CRYPTO_FUZZ_TARGET_SYMBOL macro at compile time to the
// specific fuzz_one_<mod> symbol it should dispatch to. libFuzzer's own
// main is provided by -fsanitize=fuzzer — this translation unit only
// provides LLVMFuzzerTestOneInput.
//
// This file compiles ONLY on Linux + Clang. The guard in
// src/fuzz/libfuzzer/CMakeLists.txt early-returns on any other platform
// (mirroring external/tinysha/fuzz and external/tinyaes/fuzz).
//
// Unlike the smoke driver, libFuzzer expects the target function to
// return 0 on success and does NOT want the documented-malformed-input
// exceptions to trip a fault. Wrapping the fuzz_one call in
// run_fuzz_one_safely lets libFuzzer treat SAFE-catch cases as
// "no crash, explore more" while still converting unexpected exception
// escapes into fuzzer-visible crashes via std::abort (which libFuzzer's
// crash reporter picks up with full corpus + seed reproducer).
// ---------------------------------------------------------------------------

#include "../fuzz_common.h"
#include "../fuzz_targets.h"

#include <cstdio>
#include <cstdlib>

#ifndef CRYPTO_FUZZ_TARGET_SYMBOL
#error "CRYPTO_FUZZ_TARGET_SYMBOL must be defined at compile time by the build system"
#endif

#ifndef CRYPTO_FUZZ_TARGET_NAME
#error "CRYPTO_FUZZ_TARGET_NAME must be defined at compile time by the build system"
#endif

// Forward-declare the specific target symbol this binary dispatches to.
// The declaration is identical to the ones in fuzz_targets.h — we rely on
// the build system to set CRYPTO_FUZZ_TARGET_SYMBOL to match one of those
// exported names.
extern "C" void CRYPTO_FUZZ_TARGET_SYMBOL(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const Crypto::Fuzz::FaultReport rep =
        Crypto::Fuzz::run_fuzz_one_safely(CRYPTO_FUZZ_TARGET_NAME, CRYPTO_FUZZ_TARGET_SYMBOL, data, size);

    if (rep.faulted)
    {
        // Stringify to stderr before aborting so libFuzzer's crash log
        // contains the exception type + what() for triage. libFuzzer will
        // ALSO dump the corpus input and the reproducer command — that's
        // what the user uses for escalation.
        std::fprintf(
            stderr,
            "[crypto-fuzz-%s] FAULT exception_type=%s what=%s\n",
            CRYPTO_FUZZ_TARGET_NAME,
            rep.exception_type.c_str(),
            rep.what_message.c_str());
        std::fflush(stderr);
        std::abort();
    }

    return 0;
}
