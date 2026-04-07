add_library(crypto-bulletproofs STATIC
    bulletproof_t.cpp
    bulletproofs.cpp
)
crypto_configure_target(crypto-bulletproofs)
target_link_libraries(crypto-bulletproofs PUBLIC crypto-ringct)
