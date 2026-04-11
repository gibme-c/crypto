# Save parent options before overriding for external submodules
set(_SAVE_BUILD_TEST ${BUILD_TEST})
set(_SAVE_BUILD_TESTS ${BUILD_TESTS})
set(_SAVE_BUILD_TOOLS ${BUILD_TOOLS})
set(_SAVE_BUILD_BENCH ${BUILD_BENCH})
set(_SAVE_BUILD_BENCHMARKS ${BUILD_BENCHMARKS})
set(_SAVE_BUILD_FUZZ ${BUILD_FUZZ})
set(_SAVE_BUILD_FUZZERS ${BUILD_FUZZERS})

# Force external package options off to prevent them from inheriting
# parent project settings (e.g. BUILD_TESTS=1 leaking into submodules)
set(BUILD_TEST OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(BUILD_FUZZ OFF CACHE BOOL "" FORCE)
set(BUILD_FUZZERS OFF CACHE BOOL "" FORCE)

add_subdirectory(argon2)
add_subdirectory(ed25519)
add_subdirectory(ranshaw)
add_subdirectory(serializationcpp)
add_subdirectory(tinyaes)
add_subdirectory(tinysha)
add_subdirectory(tinyblake)
add_subdirectory(randompp)

# Restore parent BUILD_TESTS option
set(BUILD_TEST ${_SAVE_BUILD_TEST} CACHE BOOL "Build test binary" FORCE)
set(BUILD_TESTS ${_SAVE_BUILD_TESTS} CACHE BOOL "Build test binary" FORCE)
set(BUILD_TOOLS ${_SAVE_BUILD_TOOLS} CACHE BOOL "Build tools binary" FORCE)
set(BUILD_BENCH ${_SAVE_BUILD_BENCH} CACHE BOOL "Build bench binary" FORCE)
set(BUILD_BENCHMARKS ${_SAVE_BUILD_BENCHMARKS} CACHE BOOL "Build benchmarks binary" FORCE)
set(BUILD_FUZZ ${_SAVE_BUILD_FUZZ} CACHE BOOL "Build fuzz binary" FORCE)
set(BUILD_FUZZERS ${_SAVE_BUILD_FUZZERS} CACHE BOOL "Build fuzz binary" FORCE)

set_property(TARGET argon2 ed25519 serialization-static ranshaw tinyaes tinysha tinyblake randompp PROPERTY FOLDER "external")

# Mark external library headers as SYSTEM so our warning flags don't fire on them
foreach(_ext_target argon2 ed25519 serialization-static tinyaes ranshaw tinysha tinyblake randompp)
    get_target_property(_inc ${_ext_target} INTERFACE_INCLUDE_DIRECTORIES)
    if(_inc)
        set_target_properties(${_ext_target} PROPERTIES
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_inc}")
    endif()
endforeach()

add_library(crypto-thirdparty INTERFACE)
target_link_libraries(crypto-thirdparty INTERFACE argon2 ed25519 serialization-static tinyaes ranshaw tinysha tinyblake randompp)

if(WIN32)
    target_link_libraries(crypto-thirdparty INTERFACE ws2_32 advapi32 crypt32 gdi32 user32)
endif()
