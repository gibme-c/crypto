add_library(crypto-helpers STATIC
    gray_code_generator_t.cpp
    hd_keys.cpp
)
crypto_configure_target(crypto-helpers)
target_link_libraries(crypto-helpers PUBLIC crypto-thirdparty)
