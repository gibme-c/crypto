// Copyright (c) 2020-2026, Brandon Lehmann
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

// ---------------------------------------------------------------------------
// fuzz_target_base58.cpp
//
// Exercises the plain Base58 and CryptoNote Base58 encode/decode/decode_check
// paths with adversarial string inputs. Both decoders return a
// {bool, deserializer_t} tuple where the bool is false on failure — they
// MUST NOT throw on any well-formed std::string input.
//
// Paths exercised (per module — Base58 and CNBase58):
//   1. decode(random string)                  — failure path returns false
//   2. decode_check(random string)            — checksum verification
//   3. encode(random bytes) round-trip         — must recover bytes
//   4. encode_check(random bytes) round-trip   — must recover bytes
//
// Both decoders have a DoS guard (CRYPTO_BASE58_MAX_INPUT_LENGTH) that
// early-rejects oversize inputs. The fuzz harness caps input size via
// read_u8_range(0, 255) which stays well below the guard, so we don't
// burn iterations on the length-reject path.
// ---------------------------------------------------------------------------

#include "fuzz_common.h"
#include "fuzz_targets.h"

#include <crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

using Crypto::Fuzz::catch_safe;
using Crypto::Fuzz::FuzzByteReader;

namespace
{
    std::string random_string(FuzzByteReader &r, size_t min_len, size_t max_len)
    {
        const size_t n = r.read_u8_range(static_cast<uint8_t>(min_len), static_cast<uint8_t>(max_len));
        const auto buf = r.read_vector(n);
        return std::string(reinterpret_cast<const char *>(buf.data()), buf.size());
    }
} // namespace

extern "C" void fuzz_one_base58(const uint8_t *data, size_t size)
{
    FuzzByteReader r(data, size);

    // -- 1. Base58::decode(random string) --
    catch_safe(
        [&]
        {
            const std::string input = random_string(r, 0, 200);
            auto [ok, reader] = Crypto::Base58::decode(input);
            (void)ok;
            (void)reader;
        });

    // -- 2. Base58::decode_check(random string) --
    catch_safe(
        [&]
        {
            const std::string input = random_string(r, 0, 200);
            auto [ok, reader] = Crypto::Base58::decode_check(input);
            (void)ok;
            (void)reader;
        });

    // -- 3. Base58 encode/decode round-trip --
    catch_safe(
        [&]
        {
            // Non-empty: both Base58 and CNBase58 decode() reject empty
            // input by contract (returns {false, {}}). The round-trip
            // invariant only holds for non-empty payloads.
            const size_t n = r.read_u8_range(1, 64);
            const std::vector<uint8_t> payload = r.read_vector(n);

            const std::string encoded = Crypto::Base58::encode(payload);
            auto [ok, reader] = Crypto::Base58::decode(encoded);

            if (!ok)
            {
                throw std::runtime_error("Base58 encode round-trip: decode returned false");
            }

            const auto recovered = reader.unread_data();
            if (recovered.size() != payload.size()
                || (payload.size() > 0 && std::memcmp(recovered.data(), payload.data(), payload.size()) != 0))
            {
                throw std::runtime_error("Base58 encode round-trip: decoded bytes do not match original");
            }
        });

    // -- 4. Base58 encode_check/decode_check round-trip --
    catch_safe(
        [&]
        {
            // Non-empty: both Base58 and CNBase58 decode() reject empty
            // input by contract (returns {false, {}}). The round-trip
            // invariant only holds for non-empty payloads.
            const size_t n = r.read_u8_range(1, 64);
            const std::vector<uint8_t> payload = r.read_vector(n);

            const std::string encoded = Crypto::Base58::encode_check(payload);
            auto [ok, reader] = Crypto::Base58::decode_check(encoded);

            if (!ok)
            {
                throw std::runtime_error("Base58 encode_check round-trip: decode_check returned false");
            }

            const auto recovered = reader.unread_data();
            if (recovered.size() != payload.size()
                || (payload.size() > 0 && std::memcmp(recovered.data(), payload.data(), payload.size()) != 0))
            {
                throw std::runtime_error("Base58 encode_check round-trip: decoded bytes do not match original");
            }
        });

    // -- 5. CNBase58::decode(random string) --
    catch_safe(
        [&]
        {
            const std::string input = random_string(r, 0, 200);
            auto [ok, reader] = Crypto::CNBase58::decode(input);
            (void)ok;
            (void)reader;
        });

    // -- 6. CNBase58::decode_check(random string) --
    catch_safe(
        [&]
        {
            const std::string input = random_string(r, 0, 200);
            auto [ok, reader] = Crypto::CNBase58::decode_check(input);
            (void)ok;
            (void)reader;
        });

    // -- 7. CNBase58 encode/decode round-trip --
    catch_safe(
        [&]
        {
            // Non-empty: both Base58 and CNBase58 decode() reject empty
            // input by contract (returns {false, {}}). The round-trip
            // invariant only holds for non-empty payloads.
            const size_t n = r.read_u8_range(1, 64);
            const std::vector<uint8_t> payload = r.read_vector(n);

            const std::string encoded = Crypto::CNBase58::encode(payload);
            auto [ok, reader] = Crypto::CNBase58::decode(encoded);

            if (!ok)
            {
                throw std::runtime_error("CNBase58 encode round-trip: decode returned false");
            }

            const auto recovered = reader.unread_data();
            if (recovered.size() != payload.size()
                || (payload.size() > 0 && std::memcmp(recovered.data(), payload.data(), payload.size()) != 0))
            {
                throw std::runtime_error("CNBase58 encode round-trip: decoded bytes do not match original");
            }
        });

    // -- 8. CNBase58 encode_check/decode_check round-trip --
    catch_safe(
        [&]
        {
            // Non-empty: both Base58 and CNBase58 decode() reject empty
            // input by contract (returns {false, {}}). The round-trip
            // invariant only holds for non-empty payloads.
            const size_t n = r.read_u8_range(1, 64);
            const std::vector<uint8_t> payload = r.read_vector(n);

            const std::string encoded = Crypto::CNBase58::encode_check(payload);
            auto [ok, reader] = Crypto::CNBase58::decode_check(encoded);

            if (!ok)
            {
                throw std::runtime_error("CNBase58 encode_check round-trip: decode_check returned false");
            }

            const auto recovered = reader.unread_data();
            if (recovered.size() != payload.size()
                || (payload.size() > 0 && std::memcmp(recovered.data(), payload.data(), payload.size()) != 0))
            {
                throw std::runtime_error("CNBase58 encode_check round-trip: decoded bytes do not match original");
            }
        });
}
