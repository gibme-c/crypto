cmake_minimum_required(VERSION 2.8.12)

if(DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "Choose the type of build, options are: Debug, Release, RelWithDebInfo")
else()
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: Debug, Release, RelWithDebInfo")
endif()

message(STATUS "Mode: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CONFIGURATION_TYPES Debug RelWithDebInfo Release CACHE STRING INTERNAL)
set(ARCH native CACHE STRING  "CPU to build for: -march value or native")

message(STATUS "Building for target architecture: ${ARCH}")

set(LIB_MAJOR_VERSION "7")
set(LIB_MINOR_VERSION "0")
set(LIB_PATCH_VERSION "3")
set(LIB_VERSION_STRING "${LIB_MAJOR_VERSION}.${LIB_MINOR_VERSION}.${LIB_PATCH_VERSION}")

if(CMAKE_VERSION VERSION_LESS 3.0)
    project(crypto CXX)
    enable_language(CXX)
else()
    cmake_policy(SET CMP0048 NEW)
    project(crypto VERSION "${LIB_VERSION_STRING}" LANGUAGES CXX)
endif()

if(NOT MSVC)
    find_program(CCACHE_PROGRAM ccache)
    if(CCACHE_PROGRAM)
        message(STATUS "Found ccache package... Activating...")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
    endif()
endif()

option(ENGLISH_ONLY "Build Only English Mnemonics" OFF)
if(DEFINED ENV{ENGLISH_ONLY})
    set(ENGLISH_ONLY $ENV{ENGLISH_ONLY})
endif()
if(ENGLISH_ONLY)
    add_compile_definitions(ENGLISH_ONLY=1)
    message(STATUS "Building Only English Mnemonics")
endif()

option(BUILD_TEST "Build test binary" OFF)
if(DEFINED ENV{BUILD_TEST})
    set(BUILD_TEST $ENV{BUILD_TEST})
endif()
if (BUILD_TEST)
    message(STATUS "Test binary added to targets list")
endif()

option(BUILD_SHARED "Build shared library in addition to static" OFF)
if(DEFINED ENV{BUILD_SHARED})
    set(BUILD_SHARED $ENV{BUILD_SHARED})
endif()
if(BUILD_SHARED)
    message(STATUS "Shared library added to targets list")
endif()

option(DEBUG_PRINT "Enable debug print statements" OFF)
if (DEFINED ENV{DEBUG_PRINT})
    set(DEBUG_PRINT $ENV{DEBUG_PRINT})
endif()
if(DEBUG_PRINT)
    add_compile_definitions(DEBUG_PRINT=1)
    message(STATUS "Activating debug print statements")
endif()

## This section describes our general CMake setup options
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_INSTALL_RULES OFF FORCE)
set(CMAKE_SKIP_PACKAGE_ALL_DEPENDENCY ON FORCE)
set(CMAKE_SUPPRESS_REGENERATION ON)
set(CMAKE_POLICY_WARNING_CMP0048 OFF)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Enable c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

## We only build static binaries -- this is left here for our dependencies
set(STATIC ON CACHE BOOL FORCE "Link libraries statically? Forced to ON")
add_definitions(-DSTATICLIB)
add_definitions(-DRAPIDJSON_HAS_STDSTRING)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /D_CRT_SECURE_NO_WARNINGS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std:c++17 /wd4267 /wd4804 /wd4996 /D_DLL /D_CRT_SECURE_NO_WARNINGS")

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
else()
    if("${ARCH}" STREQUAL "default")
        set(ARCH_FLAG "")
    else()
        set(ARCH_FLAG "-march=${ARCH}")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wuninitialized ${MAES_FLAG}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wuninitialized ${MAES_FLAG}")

    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -Og")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -Og")

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG -O3")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG -O3")

    if(APPLE)
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            # Need to build against libc++ instead of libstc++ on apple
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++ -I/usr/local/opt/llvm/include/c++/v1 -nodefaultlibs -lc++ -lc++abi -lm -lc -lgcc -lgcc_eh")

            # Need these flags so gcc OSX works on the cryptopp ASM - https://groups.google.com/forum/#!topic/cryptopp-users/po8yO-vYaac
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER=1")

        elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
            # Need to link against the llvm libc++ library, default is too old for std::filesystem
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -I/usr/local/opt/llvm/include/c++/v1")
        endif()
    endif()

    if(MINGW OR STATIC_LIBC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libstdc++")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    endif()

    if(NOT APPLE)
        set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()

add_subdirectory(external)

set(INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)

set(SOURCES
    src/encoding/languages/chinese_simplified.cpp
    src/encoding/languages/chinese_traditional.cpp
    src/encoding/languages/czech.cpp
    src/encoding/languages/english.cpp
    src/encoding/languages/french.cpp
    src/encoding/languages/italian.cpp
    src/encoding/languages/japanese.cpp
    src/encoding/languages/korean.cpp
    src/encoding/languages/language.cpp
    src/encoding/languages/portuguese.cpp
    src/encoding/languages/spanish.cpp
    src/encoding/address_encoding.cpp
    src/encoding/base58.cpp
    src/encoding/cn_base58.cpp
    src/encoding/mnemonics.cpp
    src/helpers/gray_code_generator_t.cpp
    src/helpers/hd_keys.cpp
    src/helpers/random_bytes.cpp
    src/proofs/audit.cpp
    src/proofs/bulletproofs.cpp
    src/proofs/bulletproofsplus.cpp
    src/proofs/merkle.cpp
    src/proofs/ringct.cpp
    src/signatures/rfc8032.cpp
    src/signatures/ring_signature_borromean.cpp
    src/signatures/ring_signature_clsag.cpp
    src/signatures/ring_signature_triptych.cpp
    src/signatures/signature.cpp
    src/types/crypto_borromean_signature_t.cpp
    src/types/crypto_bulletproof_plus_t.cpp
    src/types/crypto_bulletproof_t.cpp
    src/types/crypto_clsag_signature_t.cpp
    src/types/crypto_entropy_t.cpp
    src/types/crypto_hash_t.cpp
    src/types/crypto_hash_vector_t.cpp
    src/types/crypto_hd_key_t.cpp
    src/types/crypto_point_t.cpp
    src/types/crypto_point_vector_t.cpp
    src/types/crypto_secret_key_t.cpp
    src/types/crypto_scalar_t.cpp
    src/types/crypto_scalar_vector_t.cpp
    src/types/crypto_seed_t.cpp
    src/types/crypto_signature_t.cpp
    src/types/crypto_triptych_signature_t.cpp
    src/crypto_common.cpp
)

add_library(crypto-static STATIC ${SOURCES})
target_link_libraries(crypto-static ThirdParty)
target_include_directories(crypto-static PUBLIC ${INCLUDE_DIRECTORIES})

if(WIN32)
    target_link_libraries(crypto-static ws2_32 advapi32 crypt32 gdi32 user32)
endif()

if(BUILD_SHARED)
    add_library(crypto-shared STATIC ${SOURCES})
    target_link_libraries(crypto-shared ThirdParty)
    target_include_directories(crypto-shared PUBLIC ${INCLUDE_DIRECTORIES})

    if(WIN32)
        target_link_libraries(crypto-shared ws2_32 advapi32 crypt32 gdi32 user32)
    endif()
endif()

if(BUILD_TEST)
    add_executable(cryptotest src/cryptotest.cpp)
    target_link_libraries(cryptotest crypto-static)
    set_property(TARGET cryptotest PROPERTY OUTPUT_NAME "cryptotest")

    add_executable(test_slip10 src/test_slip10.cpp)
    target_link_libraries(test_slip10 crypto-static)
    set_property(TARGET test_slip10 PROPERTY OUTPUT_NAME "test_slip10")
endif()
