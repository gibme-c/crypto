add_subdirectory(argon2)
add_subdirectory(cryptopp)
add_subdirectory(ed25519)
add_subdirectory(serializationcpp)

set_property(TARGET argon2 cryptopp-static ed25519 serialization-static PROPERTY FOLDER "external")

add_library(crypto-thirdparty INTERFACE)
target_link_libraries(crypto-thirdparty INTERFACE argon2 cryptopp-static ed25519 serialization-static)

if(WIN32)
    target_link_libraries(crypto-thirdparty INTERFACE ws2_32 advapi32 crypt32 gdi32 user32)
endif()
