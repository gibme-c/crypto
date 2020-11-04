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

#ifndef CRYPTO_DEBUG_HELPER_H
#define CRYPTO_DEBUG_HELPER_H

#include <helpers/string_helper.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef DEBUG_PRINT
#define PRINTF(value)                                                        \
    {                                                                        \
        std::stringstream ss;                                                \
        ss << __FILE__ << "#" << std::to_string(__LINE__) << ": " << #value; \
        Debug::debug_printer(ss.str(), value);                               \
    }
#else
#define PRINTF(value) \
    {                 \
        (void)value;  \
    }
#endif
#ifndef RETHROW
#define RETHROW(type, message, err)                                                                             \
    {                                                                                                           \
        std::stringstream ss;                                                                                   \
        ss << __FILE__ << "#" << std::to_string(__LINE__) << ": " << std::string(message) + ": " << err.what(); \
        throw type(ss.str());                                                                                   \
    }
#endif
#ifndef SMART_CATCH
#define SMART_CATCH(type, message)      \
    catch (const std::exception &error) \
    {                                   \
        RETHROW(type, message, error);  \
    }
#endif

namespace Debug
{
    /**
     * Simple printer for debugging values
     * @param name
     * @param value
     */
    static inline void debug_print(const std::string &name, bool value)
    {
        std::cout << name << ": " << ((value) ? "true" : "false") << std::endl;
    }

    /**
     * Simple printer for debugging values
     * @tparam Type
     * @param name
     * @param values
     */
    template<typename Type>
    static inline void debug_printer(const std::string &name, const std::vector<std::vector<Type>> &values)
    {
        std::cout << name << ":" << std::endl;

        for (const auto &level1 : values)
        {
            for (const auto &value : level1)
            {
                std::cout << "\t" << value << std::endl;
            }

            std::cout << std::endl;
        }
    }

    /**
     * Simple printer for debugging values
     * @tparam Type
     * @param name
     * @param values
     */
    template<typename Type> static inline void debug_printer(const std::string &name, const std::vector<Type> &values)
    {
        std::cout << name << ":" << std::endl;

        for (const auto &value : values)
        {
            std::cout << "\t" << value << std::endl;
        }
    }

    /**
     * Simple printer for debugging values
     * @tparam Type
     * @param name
     * @param value
     */
    template<typename Type> static inline void debug_printer(const std::string &name, const Type &value)
    {
        std::cout << name << ": " << value << std::endl;
    }
} // namespace Debug

#endif
