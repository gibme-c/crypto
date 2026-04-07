add_library(crypto-borromean STATIC
    borromean.cpp
    borromean_signature_t.cpp
)
crypto_configure_target(crypto-borromean)
target_link_libraries(crypto-borromean PUBLIC crypto-ed25519)
