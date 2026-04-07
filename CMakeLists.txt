cmake_minimum_required(VERSION 3.10)

if(DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "Choose the type of build, options are: Debug, Release, RelWithDebInfo")
else()
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: Debug, Release, RelWithDebInfo")
endif()

message(STATUS "Mode: ${CMAKE_BUILD_TYPE}")

set(LIB_MAJOR_VERSION "8")
set(LIB_MINOR_VERSION "0")
set(LIB_PATCH_VERSION "0")
set(LIB_VERSION_STRING "${LIB_MAJOR_VERSION}.${LIB_MINOR_VERSION}.${LIB_PATCH_VERSION}")

project(crypto VERSION "${LIB_VERSION_STRING}" LANGUAGES C CXX)

include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)

# Replace CMake's default /W3 with nothing to avoid D9025 override warning when we set /W4
if(MSVC)
    string(REPLACE "/W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REPLACE "/W3" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "Found ccache package... Activating...")
    set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

option(ENGLISH_ONLY "Build Only English Mnemonics" OFF)
if(DEFINED ENV{ENGLISH_ONLY})
    set(ENGLISH_ONLY $ENV{ENGLISH_ONLY})
endif()
if(ENGLISH_ONLY)
    # Applied per-target below (not globally) to avoid leaking into submodules
    list(APPEND _CRYPTO_PRIVATE_DEFS ENGLISH_ONLY=1)
    message(STATUS "Building Only English Mnemonics")
endif()

option(BUILD_TESTS "Build test binary" OFF)
if(DEFINED ENV{BUILD_TESTS})
    set(BUILD_TESTS $ENV{BUILD_TESTS})
endif()
if (BUILD_TESTS)
    message(STATUS "Test binary added to targets list")
endif()

option(BUILD_BENCHMARK "Build benchmark binary" OFF)
if(DEFINED ENV{BUILD_BENCHMARK})
    set(BUILD_BENCHMARK $ENV{BUILD_BENCHMARK})
endif()
if(BUILD_BENCHMARK)
    message(STATUS "Benchmark binary added to targets list")
endif()

option(BUILD_SHARED "Build shared library in addition to static" OFF)
if(DEFINED ENV{BUILD_SHARED})
    set(BUILD_SHARED $ENV{BUILD_SHARED})
endif()
if(BUILD_SHARED)
    message(STATUS "Shared library added to targets list")
endif()

option(ENABLE_SPECTRE_MITIGATIONS "Enable MSVC Spectre mitigations (/Qspectre)" OFF)
if(DEFINED ENV{ENABLE_SPECTRE_MITIGATIONS})
    set(ENABLE_SPECTRE_MITIGATIONS $ENV{ENABLE_SPECTRE_MITIGATIONS})
endif()

## This section describes our general CMake setup options
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_SKIP_INSTALL_RULES OFF FORCE)
set(CMAKE_SKIP_PACKAGE_ALL_DEPENDENCY ON FORCE)
set(CMAKE_SUPPRESS_REGENERATION ON)

# ── Non-Apple Clang on macOS: link against the compiler's own libc++ ──
if(APPLE AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang"
        AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    get_filename_component(_clang_bin_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    get_filename_component(_clang_prefix  "${_clang_bin_dir}" DIRECTORY)

    if(EXISTS "${_clang_prefix}/lib/c++")
        message(STATUS "Non-Apple Clang detected – adding ${_clang_prefix}/lib/c++ to linker search path")
        set(_CRYPTO_CLANG_LIBCXX_DIR "${_clang_prefix}/lib/c++" CACHE INTERNAL "")
        list(APPEND CMAKE_BUILD_RPATH   "${_clang_prefix}/lib/c++")
        list(APPEND CMAKE_INSTALL_RPATH "${_clang_prefix}/lib/c++")
    endif()
endif()

# ---------------------------------------------------------------------------
# crypto_target_harden(<target> [SHARED])
# Apply security-hardening compile/link flags PRIVATE to a single target.
# Submodules are NOT affected — they handle their own flags.
#
# MinGW ABI note: only use CMake's built-in MINGW (set for GCC with MinGW).
# Clang on Windows can target either MinGW or MSVC ABI, and the linker
# varies (GNU ld vs lld-link) — applying the wrong linker flags breaks the
# build. We let Clang on Windows rely on the OS defaults for DEP/ASLR
# (enabled by default on modern Windows) rather than guessing the linker
# style.
# ---------------------------------------------------------------------------
function(crypto_target_harden TARGET_NAME)
    set(_IS_SHARED FALSE)
    if("SHARED" IN_LIST ARGN)
        set(_IS_SHARED TRUE)
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${TARGET_NAME} PRIVATE
            -Wall -Wextra -Wuninitialized -Wshadow
            -Wcast-align -Wundef
            -Wformat=2 -Wformat-security
            -fno-strict-overflow
        )

        # Stack protector (probe once, cache result)
        if(NOT DEFINED _CRYPTO_HAS_STACK_PROTECTOR)
            set(CMAKE_REQUIRED_FLAGS "-fstack-protector-strong")
            check_cxx_source_compiles(
                "int main() { char buf[64]; buf[0] = 0; return buf[0]; }"
                _CRYPTO_HAS_STACK_PROTECTOR)
            unset(CMAKE_REQUIRED_FLAGS)
            set(_CRYPTO_HAS_STACK_PROTECTOR ${_CRYPTO_HAS_STACK_PROTECTOR} CACHE INTERNAL "")
        endif()
        if(_CRYPTO_HAS_STACK_PROTECTOR)
            target_compile_options(${TARGET_NAME} PRIVATE -fstack-protector-strong)
        endif()

        # -fPIC is implied on Windows PE; only needed on ELF/Mach-O
        if(NOT WIN32)
            target_compile_options(${TARGET_NAME} PRIVATE -fPIC)
            # Stack clash protection (Linux only — not supported on macOS/Apple Clang)
            if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
                target_compile_options(${TARGET_NAME} PRIVATE -fstack-clash-protection)
            endif()
        endif()

        # Intel CET control-flow integrity (x86_64 only, probe once)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
            if(NOT DEFINED _CRYPTO_HAS_CF_PROTECTION)
                check_cxx_compiler_flag("-fcf-protection=full" _CRYPTO_HAS_CF_PROTECTION)
                set(_CRYPTO_HAS_CF_PROTECTION ${_CRYPTO_HAS_CF_PROTECTION} CACHE INTERNAL "")
            endif()
            if(_CRYPTO_HAS_CF_PROTECTION)
                target_compile_options(${TARGET_NAME} PRIVATE -fcf-protection=full)
            endif()
        endif()

        # GCC-only extras
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${TARGET_NAME} PRIVATE -Wstrict-aliasing=2)
            # GCC 13+ -Wdangling-reference false-positives on const auto& from
            # functions returning references (e.g., rapidjson get_json_value)
            target_compile_options(${TARGET_NAME} PRIVATE -Wno-dangling-reference)
            # GCC 12 -Wfree-nonheap-object false-positive when inlining
            # std::vector::push_back after reserve (loses pointer provenance)
            target_compile_options(${TARGET_NAME} PRIVATE -Wno-free-nonheap-object)
            target_compile_options(${TARGET_NAME} PRIVATE
                $<$<CONFIG:Debug>:-D_GLIBCXX_ASSERTIONS>
            )
        endif()

        # _FORTIFY_SOURCE (requires optimization; unreliable on MinGW)
        if(NOT WIN32)
            target_compile_options(${TARGET_NAME} PRIVATE
                $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
            )
        endif()

        # Linker hardening — Linux
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            set_property(TARGET ${TARGET_NAME} APPEND_STRING PROPERTY LINK_FLAGS
                " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
            # Reject undefined symbols in shared libs (catches missing exports)
            if(_IS_SHARED)
                set_property(TARGET ${TARGET_NAME} APPEND_STRING PROPERTY LINK_FLAGS
                    " -Wl,-z,defs")
            endif()
        endif()

        # Linker hardening — MinGW (DEP + ASLR)
        # Only for GCC+MinGW (MINGW is false for Clang targeting MSVC ABI)
        if(MINGW)
            set_property(TARGET ${TARGET_NAME} APPEND_STRING PROPERTY LINK_FLAGS
                " -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
        endif()

    elseif(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            /W4 /sdl /GS /guard:cf
            /wd4267 /wd4804 /wd4996
        )

        # Spectre mitigation (opt-in; significantly increases MSVC compile time)
        if(ENABLE_SPECTRE_MITIGATIONS)
            if(NOT DEFINED _CRYPTO_HAS_QSPECTRE)
                check_cxx_compiler_flag("/Qspectre" _CRYPTO_HAS_QSPECTRE)
                set(_CRYPTO_HAS_QSPECTRE ${_CRYPTO_HAS_QSPECTRE} CACHE INTERNAL "")
            endif()
            if(_CRYPTO_HAS_QSPECTRE)
                target_compile_options(${TARGET_NAME} PRIVATE /Qspectre)
            endif()
        endif()

        # DEP + ASLR
        set_property(TARGET ${TARGET_NAME} APPEND_STRING PROPERTY LINK_FLAGS
            " /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")

        # CET shadow stack (/guard:ehcont + /CETCOMPAT) is intentionally omitted.
        # It requires ALL linked object files to be compiled with /guard:ehcont,
        # which submodules (serializationcpp, etc.) are not.
    endif()
endfunction()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external)

set(_CRYPTO_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

# ---------------------------------------------------------------------------
# crypto_configure_target(<target>)
# Apply standard C++17 settings, include paths, definitions, and hardening.
# ---------------------------------------------------------------------------
function(crypto_configure_target TARGET_NAME)
    set_target_properties(${TARGET_NAME} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
    )
    target_include_directories(${TARGET_NAME} PUBLIC ${_CRYPTO_INCLUDE_DIRS})
    target_compile_definitions(${TARGET_NAME} PUBLIC RAPIDJSON_HAS_STDSTRING)
    if(_CRYPTO_PRIVATE_DEFS)
        target_compile_definitions(${TARGET_NAME} PRIVATE ${_CRYPTO_PRIVATE_DEFS})
    endif()
    if(MSVC)
        target_compile_definitions(${TARGET_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Debug>:-g3>
            $<$<CONFIG:Debug>:-Og>
            $<$<CONFIG:Release>:-O3>
        )
    endif()
    crypto_target_harden(${TARGET_NAME})
endfunction()

# ---------------------------------------------------------------------------
# crypto_configure_executable(<target>)
# Apply standard C++17 settings, optimization flags, static linking, and
# hardening to an executable target. Does NOT set include dirs or PUBLIC
# definitions (executables inherit those from crypto-static).
# ---------------------------------------------------------------------------
function(crypto_configure_executable TARGET_NAME)
    set_target_properties(${TARGET_NAME} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    if(NOT MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Debug>:-g3>
            $<$<CONFIG:Debug>:-Og>
            $<$<CONFIG:Release>:-O3>
        )
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            set_property(TARGET ${TARGET_NAME} APPEND_STRING PROPERTY
                LINK_FLAGS " -static-libgcc -static-libstdc++")
        endif()
    endif()
    if(_CRYPTO_CLANG_LIBCXX_DIR)
        set_property(TARGET ${TARGET_NAME} APPEND_STRING PROPERTY
            LINK_FLAGS " -L${_CRYPTO_CLANG_LIBCXX_DIR}")
    endif()
    crypto_target_harden(${TARGET_NAME})
endfunction()

# =========================================================================
# Component Libraries (defined in per-module CMakeLists.txt)
# =========================================================================
add_subdirectory(src/helpers)      # Layer 1
add_subdirectory(src/types)        # Layer 2
add_subdirectory(src/core)         # Layer 3
add_subdirectory(src/dleq)         # Layer 3a
add_subdirectory(src/base58)       # Layer 4a
add_subdirectory(src/addresses)    # Layer 4a
add_subdirectory(src/mnemonics)    # Layer 4a
add_subdirectory(src/slip39)       # Layer 4a
add_subdirectory(src/ed25519)         # Layer 4b
add_subdirectory(src/borromean)       # Layer 4b
add_subdirectory(src/clsag)           # Layer 4b
add_subdirectory(src/mlsag)           # Layer 4b
add_subdirectory(src/triptych)        # Layer 4b
add_subdirectory(src/adapter_signature)  # Layer 4b
add_subdirectory(src/ringct)          # Layer 4c
add_subdirectory(src/bulletproofs)    # Layer 4d
add_subdirectory(src/bulletproofsplus)  # Layer 4e
add_subdirectory(src/bulletproofspp)  # Layer 4f
add_subdirectory(src/vrf)            # Layer 4g
add_subdirectory(src/merkle)         # Layer 4h
add_subdirectory(src/integration)  # Layer 5a

# =========================================================================
# Aggregate target: crypto-static (INTERFACE linking all components)
# =========================================================================
add_library(crypto-static INTERFACE)
target_link_libraries(crypto-static INTERFACE
    crypto-integration
    crypto-ed25519
    crypto-borromean
    crypto-clsag
    crypto-mlsag
    crypto-triptych
    crypto-adapter-signature
    crypto-ringct
    crypto-bulletproofs
    crypto-bulletproofsplus
    crypto-bulletproofspp
    crypto-vrf
    crypto-merkle
    crypto-dleq
    crypto-core
    crypto-base58
    crypto-addresses
    crypto-mnemonics
    crypto-slip39
    crypto-types
    crypto-helpers
)
target_include_directories(crypto-static SYSTEM INTERFACE ${_CRYPTO_INCLUDE_DIRS})

if(BUILD_SHARED)
    # Gather sources from all component targets, resolving relative paths
    set(_ALL_SOURCES)
    foreach(_comp
        crypto-helpers crypto-types crypto-core crypto-dleq
        crypto-base58 crypto-addresses crypto-mnemonics crypto-slip39
        crypto-ed25519 crypto-borromean crypto-clsag
        crypto-mlsag crypto-triptych crypto-adapter-signature
        crypto-ringct crypto-bulletproofs
        crypto-bulletproofsplus crypto-bulletproofspp
        crypto-vrf crypto-merkle
        crypto-integration)
        get_target_property(_srcdir ${_comp} SOURCE_DIR)
        get_target_property(_srcs ${_comp} SOURCES)
        foreach(_src ${_srcs})
            if(NOT IS_ABSOLUTE "${_src}")
                list(APPEND _ALL_SOURCES "${_srcdir}/${_src}")
            else()
                list(APPEND _ALL_SOURCES "${_src}")
            endif()
        endforeach()
    endforeach()

    add_library(crypto-shared SHARED ${_ALL_SOURCES})
    crypto_configure_target(crypto-shared)
    target_link_libraries(crypto-shared PUBLIC crypto-thirdparty)
    if(_CRYPTO_CLANG_LIBCXX_DIR)
        set_property(TARGET crypto-shared APPEND_STRING PROPERTY
            LINK_FLAGS " -L${_CRYPTO_CLANG_LIBCXX_DIR}")
    endif()
    crypto_target_harden(crypto-shared SHARED)
endif()

if(BUILD_TESTS)
    add_executable(crypto-test src/test.cpp)
    target_link_libraries(crypto-test PRIVATE crypto-static)

    add_executable(crypto-slip10-test src/test_slip10.cpp)
    target_link_libraries(crypto-slip10-test PRIVATE crypto-static)

    add_executable(crypto-slip39-test src/test_slip39.cpp)
    target_link_libraries(crypto-slip39-test PRIVATE crypto-static)

    foreach(_TEST_TARGET crypto-test crypto-slip10-test crypto-slip39-test)
        crypto_configure_executable(${_TEST_TARGET})
    endforeach()
endif()

if(BUILD_BENCHMARK)
    add_executable(crypto-benchmark src/benchmark.cpp)
    target_link_libraries(crypto-benchmark PRIVATE crypto-static)
    crypto_configure_executable(crypto-benchmark)
endif()
