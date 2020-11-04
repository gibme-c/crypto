// Copyright (c) 2020, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef CRYPTO_LANGUAGE_H
#define CRYPTO_LANGUAGE_H

#include <string>
#include <vector>

namespace Crypto::Mnemonics::Language
{
    enum Language
    {
        ENGLISH = 3,
#ifndef ENGLISH_ONLY
        CHINESE_SIMPLIFIED = 0,
        CHINESE_TRADITIONAL = 1,
        CZECH = 2,
        FRENCH = 4,
        ITALIAN = 5,
        JAPANESE = 6,
        KOREAN = 7,
        PORTUGUESE = 8,
        SPANISH = 9
#endif
    };

    /**
     * Returns the mnemonic word list for the specified language
     *
     * @param language
     * @return
     */
    std::vector<std::string> select_word_list(const Language &language);

    /**
     * Returns the minimum word length for the specified language
     *
     * @param language
     * @return
     */
    size_t select_word_list_prefix(const Language &language);

    /**
     * Returns the size of the word list
     *
     * @param language
     * @return
     */
    size_t select_word_list_size(const Language &language);
} // namespace Crypto::Mnemonics::Language

#endif
