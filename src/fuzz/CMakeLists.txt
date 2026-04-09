################################################################################
# src/fuzz/CMakeLists.txt
#
# Included from the root CMakeLists.txt via add_subdirectory(src/fuzz) ONLY when
# BUILD_FUZZERS=ON. Produces:
#
#   crypto-fuzz-smoke         portable PRNG-driven smoke harness. Built on every
#                             supported compiler. Registered with CTest.
#
#   crypto-fuzz-<mod>         libFuzzer-instrumented per-module fuzzers. Built
#                             ONLY on Linux + Clang (via the subdirectory guard
#                             in libfuzzer/CMakeLists.txt). NOT registered with
#                             CTest — invoked directly by the nightly workflow.
#
# Each fuzz_one_<mod> lives in its own translation unit under
# fuzz_target_<mod>.cpp; adding a new source file to
# CRYPTO_FUZZ_TARGET_SOURCES below is the only CMake edit needed when a
# new module lands.
################################################################################

# ---------------------------------------------------------------------------
# Shared library of fuzz_one_<mod> definitions + the common helpers. This
# static library is linked into both the portable smoke driver and every
# libFuzzer per-target binary, so each fuzz body exists in exactly one
# translation unit regardless of front-end.
# ---------------------------------------------------------------------------
set(CRYPTO_FUZZ_COMMON_SOURCES
    fuzz_common.cpp
)

# The per-module fuzz target sources. Each target has its own translation
# unit.
set(CRYPTO_FUZZ_TARGET_SOURCES
    # --- types layer ---
    fuzz_target_scalar.cpp
    fuzz_target_point.cpp
    fuzz_target_hash.cpp
    fuzz_target_entropy.cpp
    fuzz_target_hd_keys.cpp

    # --- core layer ---
    fuzz_target_aes.cpp
    fuzz_target_transcript.cpp

    # --- encoding layer ---
    fuzz_target_base58.cpp
    fuzz_target_addresses.cpp
    fuzz_target_mnemonics.cpp
    fuzz_target_slip39.cpp

    # --- signature layer ---
    fuzz_target_signature.cpp
    fuzz_target_rfc8032.cpp
    fuzz_target_dleq.cpp
    fuzz_target_adapter.cpp

    # --- ring signatures ---
    fuzz_target_borromean.cpp
    fuzz_target_clsag.cpp
    fuzz_target_mlsag.cpp
    fuzz_target_triptych.cpp

    # --- range proofs ---
    fuzz_target_bp.cpp
    fuzz_target_bpplus.cpp
    fuzz_target_bppp.cpp

    # --- higher-level ---
    fuzz_target_ringct.cpp
    fuzz_target_vrf.cpp
    fuzz_target_merkle.cpp
    fuzz_target_audit.cpp
)

add_library(crypto-fuzz-targets STATIC
    ${CRYPTO_FUZZ_COMMON_SOURCES}
    ${CRYPTO_FUZZ_TARGET_SOURCES}
)
target_link_libraries(crypto-fuzz-targets PUBLIC crypto-static)
target_include_directories(crypto-fuzz-targets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# crypto_configure_target is the library-side helper (sets C++17,
# POSITION_INDEPENDENT_CODE, include paths, definitions, and hardening).
# Using the executable helper on a static library is almost-equivalent
# but leaves out PIC which libFuzzer shared-library consumers want.
crypto_configure_target(crypto-fuzz-targets)
crypto_enable_sanitizers_if_requested(crypto-fuzz-targets)

# Silence the MSVC-CRT getenv/sprintf deprecation warnings. Defined on all
# Windows builds because Clang-on-Windows also consumes the same MSVC CRT
# headers that emit these pragmas, even though CMAKE_CXX_COMPILER_ID is
# "Clang" rather than "MSVC". Harmless on Linux/macOS (the macro is
# Microsoft-specific and ignored by libstdc++/libc++).
if(WIN32)
    target_compile_definitions(crypto-fuzz-targets PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# ---------------------------------------------------------------------------
# crypto-fuzz-smoke — portable PRNG-driven smoke harness.
#
# Built on every compiler. Registered with CTest via add_test so it runs as
# part of the existing test matrix whenever BUILD_FUZZERS=ON. Iteration
# count is intentionally low by default so CI stays predictable — longer
# runs happen in the nightly libFuzzer workflow.
# ---------------------------------------------------------------------------
add_executable(crypto-fuzz-smoke smoke_main.cpp)
target_link_libraries(crypto-fuzz-smoke PRIVATE crypto-fuzz-targets)
crypto_configure_executable(crypto-fuzz-smoke)
crypto_enable_sanitizers_if_requested(crypto-fuzz-smoke)

if(WIN32)
    target_compile_definitions(crypto-fuzz-smoke PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_test(NAME crypto-fuzz-smoke COMMAND crypto-fuzz-smoke)

# Give the smoke harness a generous-but-bounded deadline. If a crash ever
# makes one target hang, CTest's timeout is the only thing that will kill
# it — keep this conservative enough to always abort before CI times out,
# but long enough that the default 500 iterations × 26 targets always
# fit comfortably.
set_tests_properties(crypto-fuzz-smoke PROPERTIES
    TIMEOUT 300
)

# ---------------------------------------------------------------------------
# libFuzzer per-target binaries (Linux + Clang only)
#
# The subdirectory's CMakeLists.txt early-returns on any other platform,
# mirroring external/tinysha/fuzz and external/tinyaes/fuzz. On Linux+Clang
# it produces one crypto-fuzz-<mod> binary per CRYPTO_FUZZ_TARGET_LIST
# entry, each instrumented with -fsanitize=fuzzer,address,undefined.
# ---------------------------------------------------------------------------
add_subdirectory(libfuzzer)

# ---------------------------------------------------------------------------
# Dev-time seed corpus generator (not built unless BUILD_TESTS is also ON).
# Produces crypto-fuzz-seed-generator under <build>/fuzz/. Used to (re)write
# the committed src/fuzz/corpus/<target>/seed-NN.bin tree. Not registered
# with CTest.
# ---------------------------------------------------------------------------
add_subdirectory(corpus)
