# slip39_english.cpp is a pure-data wordlist TU (single function returning
# a std::vector<std::string> from a braced UTF-8 string-literal list with
# 1024 entries). It is split into its own STATIC library so it can be
# excluded from sanitizer instrumentation at the build-graph level,
# matching the treatment in src/mnemonics/CMakeLists.txt. See the rationale
# there — instrumenting these wordlists under ASan+UBSan provides zero
# bug-finding value and pushes peak compile RAM above the ubuntu-latest
# runner ceiling.
add_library(crypto-slip39-wordlist STATIC
    slip39_english.cpp
)
crypto_configure_target(crypto-slip39-wordlist)

add_library(crypto-slip39 STATIC
    slip39.cpp
)
crypto_configure_target(crypto-slip39)
target_link_libraries(crypto-slip39 PUBLIC crypto-mnemonics crypto-slip39-wordlist)
