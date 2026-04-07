add_library(crypto-base58 STATIC
    base58.cpp
    cn_base58.cpp
)
crypto_configure_target(crypto-base58)
target_link_libraries(crypto-base58 PUBLIC crypto-core)
