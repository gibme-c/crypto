add_library(crypto-merkle STATIC
    merkle.cpp
)
crypto_configure_target(crypto-merkle)
target_link_libraries(crypto-merkle PUBLIC crypto-core)
