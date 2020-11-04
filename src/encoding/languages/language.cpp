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

#ifndef ENGLISH_ONLY
#include <encoding/languages/chinese_simplified.h>
#include <encoding/languages/chinese_traditional.h>
#include <encoding/languages/czech.h>
#include <encoding/languages/french.h>
#include <encoding/languages/italian.h>
#include <encoding/languages/japanese.h>
#include <encoding/languages/korean.h>
#include <encoding/languages/portuguese.h>
#include <encoding/languages/spanish.h>
#endif
#include <encoding/languages/english.h>
#include <encoding/languages/language.h>
#include <stdexcept>

static inline size_t WORD_MAX_LENGTH = 100;

namespace Crypto::Mnemonics::Language
{
    std::vector<std::string> select_word_list(const Language &language)
    {
        switch (language)
        {
            case ENGLISH:
                return English::word_list();
#ifndef ENGLISH_ONLY
            case CHINESE_SIMPLIFIED:
                return Chinese::Simplified::word_list();
            case CHINESE_TRADITIONAL:
                return Chinese::Traditional::word_list();
            case CZECH:
                return Czech::word_list();
            case FRENCH:
                return French::word_list();
            case ITALIAN:
                return Italian::word_list();
            case JAPANESE:
                return Japanese::word_list();
            case KOREAN:
                return Korean::word_list();
            case PORTUGUESE:
                return Portuguese::word_list();
            case SPANISH:
                return Spanish::word_list();
#endif
            default:
                throw std::invalid_argument(std::string("Invalid language specified"));
        }
    }

    size_t select_word_list_prefix(const Language &language)
    {
        switch (language)
        {
            case ENGLISH:
                return 4;
#ifndef ENGLISH_ONLY
            case CZECH:
            case FRENCH:
            case ITALIAN:
            case PORTUGUESE:
            case SPANISH:
                return 4;
            case CHINESE_SIMPLIFIED:
            case CHINESE_TRADITIONAL:
            case JAPANESE:
            case KOREAN:
                return WORD_MAX_LENGTH;
#endif
            default:
                return WORD_MAX_LENGTH;
        }
    }

    size_t select_word_list_size(const Language &language)
    {
        const auto words = select_word_list(language);

        return words.size();
    }
} // namespace Crypto::Mnemonics::Language
