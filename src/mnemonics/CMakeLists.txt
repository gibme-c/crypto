# entropy_t and seed_t live in src/types/ but compile here (they depend on mnemonics)
add_library(crypto-mnemonics STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/types/entropy_t.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/types/seed_t.cpp
    mnemonics.cpp
    languages/chinese_simplified.cpp
    languages/chinese_traditional.cpp
    languages/czech.cpp
    languages/english.cpp
    languages/french.cpp
    languages/italian.cpp
    languages/japanese.cpp
    languages/korean.cpp
    languages/language.cpp
    languages/portuguese.cpp
    languages/spanish.cpp
)
crypto_configure_target(crypto-mnemonics)
target_link_libraries(crypto-mnemonics PUBLIC crypto-core)
