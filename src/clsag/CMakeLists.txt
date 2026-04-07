add_library(crypto-clsag STATIC
    clsag.cpp
    clsag_signature_t.cpp
)
crypto_configure_target(crypto-clsag)
target_link_libraries(crypto-clsag PUBLIC crypto-core)
