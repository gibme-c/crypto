add_library(crypto-bulletproofspp STATIC
    bulletproof_pp_t.cpp
    bulletproofspp.cpp
)
crypto_configure_target(crypto-bulletproofspp)
target_link_libraries(crypto-bulletproofspp PUBLIC crypto-ringct)
