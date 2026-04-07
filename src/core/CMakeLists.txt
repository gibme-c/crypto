add_library(crypto-core STATIC
    crypto_common.cpp
)
crypto_configure_target(crypto-core)
target_link_libraries(crypto-core PUBLIC crypto-types)
