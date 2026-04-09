################################################################################
# src/fuzz/corpus/CMakeLists.txt
#
# Builds the dev-time seed corpus generator. NOT registered with CTest. NOT
# part of any normal build artifact set. Only built when BUILD_FUZZERS=ON
# AND BUILD_TESTS=ON, since the generator is a developer tool used to
# regenerate the committed seed tree under src/fuzz/corpus/<target>/.
#
# Usage (from a build directory):
#   cmake --build . --target crypto-fuzz-seed-generator
#   ./fuzz/crypto-fuzz-seed-generator <source>/src/fuzz/corpus/
#
# The generator is library-independent on purpose: it does not link against
# crypto-static. Seed contents are deterministic byte streams from a
# stdlib-only PRNG, not library serializations. This keeps regeneration
# fast, removes any cross-platform serialization-format dependency, and
# means the generator survives library API changes.
################################################################################

if(NOT BUILD_FUZZERS OR NOT BUILD_TESTS)
    return()
endif()

add_executable(crypto-fuzz-seed-generator generate_seeds.cpp)
crypto_configure_executable(crypto-fuzz-seed-generator)

# No CTest registration on purpose. The generator is a manual dev tool.

set_target_properties(crypto-fuzz-seed-generator PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz"
)

if(WIN32)
    target_compile_definitions(crypto-fuzz-seed-generator PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
