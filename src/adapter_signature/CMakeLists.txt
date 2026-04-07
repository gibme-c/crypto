add_library(crypto-adapter-signature STATIC
    adapter_signature.cpp
    adapter_signature_t.cpp
    adapted_signature_t.cpp
)
crypto_configure_target(crypto-adapter-signature)
target_link_libraries(crypto-adapter-signature PUBLIC crypto-ed25519 crypto-dleq)
