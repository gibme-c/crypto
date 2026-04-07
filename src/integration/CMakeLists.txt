add_library(crypto-integration STATIC
    audit.cpp
)
crypto_configure_target(crypto-integration)
target_link_libraries(crypto-integration PUBLIC crypto-clsag crypto-base58)
