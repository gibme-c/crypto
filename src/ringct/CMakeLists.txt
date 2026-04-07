add_library(crypto-ringct STATIC
    ringct.cpp
)
crypto_configure_target(crypto-ringct)
target_link_libraries(crypto-ringct PUBLIC crypto-core)
