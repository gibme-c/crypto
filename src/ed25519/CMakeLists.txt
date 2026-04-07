add_library(crypto-ed25519 STATIC
    rfc8032.cpp
    signature.cpp
    signature_t.cpp
)
crypto_configure_target(crypto-ed25519)
target_link_libraries(crypto-ed25519 PUBLIC crypto-core)
