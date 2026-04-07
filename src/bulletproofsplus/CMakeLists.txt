add_library(crypto-bulletproofsplus STATIC
    bulletproof_plus_t.cpp
    bulletproofsplus.cpp
)
crypto_configure_target(crypto-bulletproofsplus)
target_link_libraries(crypto-bulletproofsplus PUBLIC crypto-ringct)
