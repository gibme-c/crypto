add_library(crypto-triptych STATIC
    triptych.cpp
    triptych_signature_t.cpp
)
crypto_configure_target(crypto-triptych)
target_link_libraries(crypto-triptych PUBLIC crypto-core)
