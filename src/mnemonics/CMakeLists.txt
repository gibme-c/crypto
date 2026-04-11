# Wordlist TUs are split into their own STATIC library so they can be
# excluded from sanitizer instrumentation at the build-graph level.
# Each language file is a single function returning a std::vector<std::string>
# built from a braced UTF-8 string-literal list — zero runtime logic and
# zero bug-finding value under ASan/UBSan. Instrumenting them pushes peak
# compile RAM above the GitHub Actions ~7 GB ubuntu-latest ceiling (worst
# offenders: korean.cpp at 2,083 lines / ~11K entries, and the two
# chinese_*.cpp files). Keeping this as a separate target is structurally
# self-documenting and robust against adding an 11th language file.
add_library(crypto-mnemonics-wordlists STATIC
    languages/chinese_simplified.cpp
    languages/chinese_traditional.cpp
    languages/czech.cpp
    languages/english.cpp
    languages/french.cpp
    languages/italian.cpp
    languages/japanese.cpp
    languages/korean.cpp
    languages/portuguese.cpp
    languages/spanish.cpp
)
crypto_configure_target(crypto-mnemonics-wordlists)

# entropy_t and seed_t live in src/types/ but compile here (they depend on mnemonics)
add_library(crypto-mnemonics STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/types/entropy_t.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/types/seed_t.cpp
    mnemonics.cpp
    languages/language.cpp
)
crypto_configure_target(crypto-mnemonics)
target_link_libraries(crypto-mnemonics PUBLIC crypto-core crypto-mnemonics-wordlists)
