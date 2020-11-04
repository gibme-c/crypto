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

#ifndef CRYPTO_SIGNATURE_RFC8032_H
#define CRYPTO_SIGNATURE_RFC8032_H

#include <types/crypto_signature_t.h>

namespace Crypto::RFC8032
{
    /**
     * Checks that the supplied signature was generated with the private key for the given public key
     * @param message
     * @param message_length
     * @param public_key
     * @param signature
     * @return
     */
    bool check_signature(
        const void *message,
        size_t message_length,
        const crypto_public_key_t &public_key,
        const crypto_signature_t &signature);

    /**
     * Checks that the supplied signature was generated with the private key for the given public key
     * @tparam T
     * @param message
     * @param public_key
     * @param signature
     * @return
     */
    template<typename T>
    bool check_signature(const T &message, const crypto_public_key_t &public_key, const crypto_signature_t &signature)
    {
        return check_signature(message.data(), message.size(), public_key, signature);
    }

    /**
     * Generates a single ED25519 signature using the secret key supplied
     * @param message
     * @param message_length
     * @param secret_key
     * @return
     */
    crypto_signature_t
        generate_signature(const void *message, size_t message_length, const crypto_scalar_t &secret_key);

    /**
     * Generates a single ED25519 signature using the secret key supplied
     * @tparam T
     * @param message
     * @param secret_key
     * @return
     */
    template<typename T> crypto_signature_t generate_signature(const T &message, const crypto_scalar_t &secret_key)
    {
        return generate_signature(message.data(), message.size(), secret_key);
    }
} // namespace Crypto::RFC8032

#endif
