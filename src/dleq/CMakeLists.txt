add_library(crypto-dleq STATIC
    dleq.cpp
    dleq_proof_t.cpp
)
crypto_configure_target(crypto-dleq)
target_link_libraries(crypto-dleq PUBLIC crypto-core)
