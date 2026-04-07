add_library(crypto-addresses STATIC
    address_encoding.cpp
)
crypto_configure_target(crypto-addresses)
target_link_libraries(crypto-addresses PUBLIC crypto-base58)
