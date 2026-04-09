################################################################################
# src/fuzz/libfuzzer/CMakeLists.txt
#
# libFuzzer per-target binaries. Built ONLY on Linux + Clang because
# -fsanitize=fuzzer is a Clang-specific instrumentation that doesn't ship
# with MSVC, MinGW GCC, or Apple Clang. This guard mirrors
# external/tinysha/fuzz/CMakeLists.txt and external/tinyaes/fuzz/CMakeLists.txt
# byte-for-byte — do not invent a new gate.
################################################################################

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    return()
endif()
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()

message(STATUS "[crypto] libFuzzer front-end enabled (Linux + Clang)")

# ---------------------------------------------------------------------------
# Per-target binary list. Each entry must match a fuzz_one_<mod> declared
# in src/fuzz/fuzz_targets.h. Adding a new target here requires ONLY a new
# line in the list below — the build rule is shared.
#
# Order matches the layering order in src/fuzz/fuzz_targets.h for visual
# consistency. Keep them in sync.
# ---------------------------------------------------------------------------
set(CRYPTO_LIBFUZZER_TARGETS
    scalar
    point
    hash
    entropy
    hd_keys
    aes
    transcript
    base58
    addresses
    mnemonics
    slip39
    signature
    rfc8032
    dleq
    adapter
    borromean
    clsag
    mlsag
    triptych
    ringct
    bp
    bpplus
    bppp
    vrf
    merkle
    audit
)

# Sanitizers for libFuzzer binaries. address + undefined are the minimum for
# a crypto library fuzz run — memory is available too but has a high perf
# cost and significant overlap with ASAN for our usage. MSAN is added only
# when a specific target warrants it.
set(CRYPTO_LIBFUZZER_SANITIZERS "fuzzer,address,undefined")
set(CRYPTO_LIBFUZZER_FLAGS
    -fsanitize=${CRYPTO_LIBFUZZER_SANITIZERS}
    -fno-omit-frame-pointer
    -O1
    -g
)

foreach(_tgt IN LISTS CRYPTO_LIBFUZZER_TARGETS)
    set(_bin "crypto-fuzz-${_tgt}")

    add_executable(${_bin} libfuzzer_main.cpp)

    # Each binary hard-codes which fuzz_one_<mod> it dispatches to via
    # preprocessor defines consumed by libfuzzer_main.cpp. This avoids a
    # per-target source file — one shim compiles 26 different ways.
    target_compile_definitions(${_bin} PRIVATE
        CRYPTO_FUZZ_TARGET_SYMBOL=fuzz_one_${_tgt}
        CRYPTO_FUZZ_TARGET_NAME="${_tgt}"
    )

    target_include_directories(${_bin} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    )

    target_link_libraries(${_bin} PRIVATE crypto-fuzz-targets)

    set_target_properties(${_bin} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fuzz
    )

    target_compile_options(${_bin} PRIVATE ${CRYPTO_LIBFUZZER_FLAGS})
    target_link_options   (${_bin} PRIVATE ${CRYPTO_LIBFUZZER_FLAGS})
endforeach()

# NOTE: we do NOT rebuild crypto-static with matching sanitizer flags here.
# A libFuzzer run against a non-instrumented library will still find
# crashes, uncaught exceptions, and sanitizer-detectable bugs in the fuzz
# target itself AND in any inlined crypto-static code, but it will not
# produce coverage-guided exploration of library code paths. A full
# instrumented-library nightly build can be layered on top via a dedicated
# sub-build when coverage-guided exploration is required.
