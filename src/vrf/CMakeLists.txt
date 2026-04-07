add_library(crypto-vrf STATIC
    vrf.cpp
    vrf_proof_t.cpp
)
crypto_configure_target(crypto-vrf)
target_link_libraries(crypto-vrf PUBLIC crypto-core)
