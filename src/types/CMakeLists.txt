# NOTE: entropy_t and seed_t are compiled in crypto-mnemonics (they depend on mnemonics)
add_library(crypto-types STATIC
    hash_t.cpp
    hash_vector_t.cpp
    hd_key_t.cpp
    point_t.cpp
    point_vector_t.cpp
    scalar_t.cpp
    scalar_vector_t.cpp
    secret_key_t.cpp
)
crypto_configure_target(crypto-types)
target_link_libraries(crypto-types PUBLIC crypto-helpers)
