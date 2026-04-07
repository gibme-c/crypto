add_library(crypto-mlsag STATIC
    mlsag.cpp
    mlsag_signature_t.cpp
)
crypto_configure_target(crypto-mlsag)
target_link_libraries(crypto-mlsag PUBLIC crypto-core)
