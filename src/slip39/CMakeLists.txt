add_library(crypto-slip39 STATIC
    slip39.cpp
    slip39_english.cpp
)
crypto_configure_target(crypto-slip39)
target_link_libraries(crypto-slip39 PUBLIC crypto-mnemonics)
