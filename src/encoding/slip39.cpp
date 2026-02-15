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

/**
 * @file slip39.cpp
 * @brief SLIP-39 Shamir's Secret Sharing implementation.
 *
 * Implements GF(256) arithmetic, Shamir secret sharing, RS1024 checksums,
 * Feistel cipher with PBKDF2, and mnemonic encoding/decoding per the SLIP-39 spec.
 */

#include <algorithm>
#include <cryptopp/hmac.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cstring>
#include <encoding/languages/slip39_english.h>
#include <encoding/slip39.h>
#include <helpers/random_bytes.h>
#include <map>
#include <numeric>
#include <stdexcept>

// ============================================================================
// Constants
// ============================================================================

static constexpr size_t RADIX_BITS = 10;
static constexpr size_t RADIX = 1024;
static constexpr size_t ID_BITS = 15;
static constexpr size_t ITERATION_EXP_BITS = 4;
static constexpr size_t EXTENDABLE_BIT = 1;
static constexpr size_t GROUP_INDEX_BITS = 4;
static constexpr size_t GROUP_THRESHOLD_BITS = 4;
static constexpr size_t GROUP_COUNT_BITS = 4;
static constexpr size_t MEMBER_INDEX_BITS = 4;
static constexpr size_t MEMBER_THRESHOLD_BITS = 4;
static constexpr size_t CHECKSUM_WORDS = 3;
static constexpr size_t CHECKSUM_BITS = CHECKSUM_WORDS * RADIX_BITS;
static constexpr size_t MIN_STRENGTH_BITS = 128;
static constexpr size_t DIGEST_INDEX = 254;
static constexpr size_t SECRET_INDEX = 255;
static constexpr size_t DIGEST_LENGTH = 4;
static constexpr size_t BASE_ITERATION_COUNT = 2500;
static constexpr size_t MAX_SHARE_COUNT = 16;

// Header: id(15) + extendable(1) + iteration_exp(4) + group_index(4) +
//         group_threshold(4) + group_count(4) + member_index(4) + member_threshold(4) = 40 bits
static constexpr size_t HEADER_BITS = ID_BITS + EXTENDABLE_BIT + ITERATION_EXP_BITS + GROUP_INDEX_BITS
                                      + GROUP_THRESHOLD_BITS + GROUP_COUNT_BITS + MEMBER_INDEX_BITS
                                      + MEMBER_THRESHOLD_BITS;

// ============================================================================
// Internal share structure
// ============================================================================

struct slip39_share_t
{
    uint16_t identifier = 0;
    bool extendable = true;
    uint8_t iteration_exponent = 0;
    uint8_t group_index = 0;
    uint8_t group_threshold = 0;
    uint8_t group_count = 0;
    uint8_t member_index = 0;
    uint8_t member_threshold = 0;
    std::vector<uint8_t> value;
};

// ============================================================================
// GF(256) Arithmetic -- Rijndael field (x^8 + x^4 + x^3 + x + 1)
// ============================================================================

static constexpr uint16_t GF256_POLY = 0x11b; // x^8 + x^4 + x^3 + x + 1

// Log and exp tables for GF(256) with generator 0x03
static uint8_t gf256_log_table[256];
static uint8_t gf256_exp_table[512]; // doubled for convenience
static bool gf256_tables_initialized = false;

static void gf256_init_tables()
{
    if (gf256_tables_initialized)
    {
        return;
    }

    std::memset(gf256_log_table, 0, sizeof(gf256_log_table));
    std::memset(gf256_exp_table, 0, sizeof(gf256_exp_table));

    uint16_t x = 1;

    for (int i = 0; i < 255; ++i)
    {
        gf256_exp_table[i] = static_cast<uint8_t>(x);
        gf256_log_table[x] = static_cast<uint8_t>(i);

        x ^= (x << 1) ^ ((x >> 7) * GF256_POLY);
        x &= 0xff;
    }

    // Extend exp table for easy modular lookups
    for (int i = 255; i < 512; ++i)
    {
        gf256_exp_table[i] = gf256_exp_table[i - 255];
    }

    gf256_tables_initialized = true;
}

static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0)
    {
        return 0;
    }

    return gf256_exp_table[gf256_log_table[a] + gf256_log_table[b]];
}

static uint8_t gf256_pow(uint8_t base, uint8_t exp)
{
    if (exp == 0)
    {
        return 1;
    }

    if (base == 0)
    {
        return 0;
    }

    int log_result = (static_cast<int>(gf256_log_table[base]) * exp) % 255;

    return gf256_exp_table[log_result];
}

// ============================================================================
// Shamir's Secret Sharing in GF(256)
// ============================================================================

// Evaluate polynomial at x using Horner's method, per byte position
static uint8_t evaluate_polynomial(const std::vector<std::vector<uint8_t>> &coefficients, size_t byte_pos, uint8_t x)
{
    // coefficients[0] is the secret (constant term), coefficients[degree] is highest
    // Horner's: result = c[n]*x + c[n-1], then *x + c[n-2], etc.
    uint8_t result = 0;

    for (int i = static_cast<int>(coefficients.size()) - 1; i >= 0; --i)
    {
        result = gf256_mul(result, x) ^ coefficients[i][byte_pos];
    }

    return result;
}

// Lagrange interpolation at x for given (xi, yi) pairs, per byte position
static uint8_t lagrange_interpolate(
    const std::vector<uint8_t> &x_coords,
    const std::vector<std::vector<uint8_t>> &y_values,
    size_t byte_pos,
    uint8_t x)
{
    const size_t n = x_coords.size();

    uint8_t result = 0;

    for (size_t i = 0; i < n; ++i)
    {
        // Compute Lagrange basis polynomial L_i(x)
        uint8_t basis = 1;

        for (size_t j = 0; j < n; ++j)
        {
            if (i == j)
            {
                continue;
            }

            // basis *= (x - x_j) / (x_i - x_j)
            const uint8_t num = x ^ x_coords[j];
            const uint8_t den = x_coords[i] ^ x_coords[j];

            if (den == 0)
            {
                throw std::invalid_argument("Duplicate share indices");
            }

            // Division in GF(256): a/b = exp(log(a) - log(b))
            if (num == 0)
            {
                basis = 0;
                break;
            }

            int log_div = (gf256_log_table[num] - gf256_log_table[den] + 255) % 255;

            basis = gf256_mul(basis, gf256_exp_table[log_div]);
        }

        result ^= gf256_mul(basis, y_values[i][byte_pos]);
    }

    return result;
}

// Split secret into shares
static std::vector<std::pair<uint8_t, std::vector<uint8_t>>>
    shamir_split(const std::vector<uint8_t> &secret, size_t threshold, size_t total_shares)
{
    const size_t secret_len = secret.size();

    // Generate random coefficients for polynomial (degree = threshold - 1)
    // coefficient[0] = digest||random, coefficient[threshold-1] used for shares
    // The secret is at index SECRET_INDEX (255), digest at DIGEST_INDEX (254)

    // Generate random bytes for the digest share
    std::vector<uint8_t> random_part(secret_len - DIGEST_LENGTH);
    random_bytes(random_part.size(), random_part.data());

    // Compute digest: HMAC-SHA256(random_part, secret)[0:4]
    std::vector<uint8_t> digest_value(secret_len);
    {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(random_part.data(), random_part.size());

        hmac.Update(secret.data(), secret.size());

        uint8_t hmac_out[32];
        hmac.Final(hmac_out);

        std::memcpy(digest_value.data(), hmac_out, DIGEST_LENGTH);
        std::memcpy(digest_value.data() + DIGEST_LENGTH, random_part.data(), random_part.size());
    }

    // We need to create a polynomial where:
    //   f(SECRET_INDEX) = secret
    //   f(DIGEST_INDEX) = digest_value
    // And shares are f(0), f(1), ..., f(total_shares-1)

    // Build shares by Lagrange interpolation from the fixed points plus random coefficients
    // For threshold T, we have T points defining the polynomial:
    //   - (SECRET_INDEX, secret)
    //   - (DIGEST_INDEX, digest_value)
    //   - (random x values, random y values) for the remaining T-2 points

    // Actually, the SLIP-39 spec uses a simpler approach:
    // Generate T-2 random share values at indices 0..T-3, then the polynomial is
    // defined by these T-2 random shares + secret at 255 + digest at 254 = T points total.

    // But for threshold=1, we just copy the secret directly.
    if (threshold == 1)
    {
        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> shares;

        for (size_t i = 0; i < total_shares; ++i)
        {
            shares.emplace_back(static_cast<uint8_t>(i), secret);
        }

        return shares;
    }

    // For threshold >= 2:
    // Build T base shares: secret at 255, digest at 254, and T-2 random shares
    std::vector<uint8_t> base_x;
    std::vector<std::vector<uint8_t>> base_y;

    // Add secret point
    base_x.push_back(SECRET_INDEX);
    base_y.push_back(secret);

    // Add digest point
    base_x.push_back(DIGEST_INDEX);
    base_y.push_back(digest_value);

    // Add T-2 random shares at indices that won't collide with output indices
    // Use indices starting from total_shares to avoid collisions
    for (size_t i = 0; i < threshold - 2; ++i)
    {
        const uint8_t idx = static_cast<uint8_t>(total_shares + i);

        std::vector<uint8_t> rand_val(secret_len);
        random_bytes(rand_val.size(), rand_val.data());

        base_x.push_back(idx);
        base_y.push_back(rand_val);
    }

    // Now interpolate to get shares at indices 0..total_shares-1
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> shares;

    for (size_t i = 0; i < total_shares; ++i)
    {
        std::vector<uint8_t> share_value(secret_len);

        for (size_t b = 0; b < secret_len; ++b)
        {
            share_value[b] = lagrange_interpolate(base_x, base_y, b, static_cast<uint8_t>(i));
        }

        shares.emplace_back(static_cast<uint8_t>(i), share_value);
    }

    return shares;
}

// Combine shares to recover secret
static std::vector<uint8_t> shamir_combine(
    const std::vector<uint8_t> &x_coords,
    const std::vector<std::vector<uint8_t>> &share_values,
    size_t threshold)
{
    if (x_coords.size() < threshold)
    {
        throw std::invalid_argument("Not enough shares to reconstruct secret");
    }

    const size_t secret_len = share_values[0].size();

    if (threshold == 1)
    {
        return share_values[0];
    }

    // Recover secret at index SECRET_INDEX (255)
    std::vector<uint8_t> secret(secret_len);

    for (size_t b = 0; b < secret_len; ++b)
    {
        secret[b] = lagrange_interpolate(x_coords, share_values, b, SECRET_INDEX);
    }

    // Recover digest at index DIGEST_INDEX (254)
    std::vector<uint8_t> digest_value(secret_len);

    for (size_t b = 0; b < secret_len; ++b)
    {
        digest_value[b] = lagrange_interpolate(x_coords, share_values, b, DIGEST_INDEX);
    }

    // Verify digest: HMAC-SHA256(random_part, secret)[0:4] must match
    const uint8_t *random_part = digest_value.data() + DIGEST_LENGTH;
    const size_t random_len = secret_len - DIGEST_LENGTH;

    CryptoPP::HMAC<CryptoPP::SHA256> hmac(random_part, random_len);

    hmac.Update(secret.data(), secret.size());

    uint8_t hmac_out[32];
    hmac.Final(hmac_out);

    if (std::memcmp(digest_value.data(), hmac_out, DIGEST_LENGTH) != 0)
    {
        throw std::runtime_error("Share digest verification failed -- wrong passphrase or corrupted shares");
    }

    return secret;
}

// ============================================================================
// RS1024 Checksum
// ============================================================================

static const uint32_t RS1024_GEN[10] =
    {0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120};

static uint32_t rs1024_polymod(const std::vector<uint16_t> &values)
{
    uint32_t chk = 1;

    for (const auto v : values)
    {
        const uint8_t b = static_cast<uint8_t>(chk >> 20);

        chk = ((chk & 0xfffff) << 10) ^ v;

        for (int i = 0; i < 10; ++i)
        {
            if ((b >> i) & 1)
            {
                chk ^= RS1024_GEN[i];
            }
        }
    }

    return chk;
}

static std::vector<uint16_t> rs1024_customization(bool extendable)
{
    const std::string cs = extendable ? "shamir_extendable" : "shamir";
    std::vector<uint16_t> result;

    for (const char c : cs)
    {
        result.push_back(static_cast<uint16_t>(c));
    }

    return result;
}

static std::vector<uint16_t> rs1024_create_checksum(const std::vector<uint16_t> &data, bool extendable)
{
    auto values = rs1024_customization(extendable);
    values.insert(values.end(), data.begin(), data.end());

    // Append 3 zero words for checksum space
    for (size_t i = 0; i < CHECKSUM_WORDS; ++i)
    {
        values.push_back(0);
    }

    const uint32_t polymod = rs1024_polymod(values) ^ 1;

    std::vector<uint16_t> checksum(CHECKSUM_WORDS);

    for (size_t i = 0; i < CHECKSUM_WORDS; ++i)
    {
        checksum[i] = static_cast<uint16_t>((polymod >> (10 * (CHECKSUM_WORDS - 1 - i))) & 0x3ff);
    }

    return checksum;
}

static bool rs1024_verify_checksum(const std::vector<uint16_t> &data, bool extendable)
{
    auto values = rs1024_customization(extendable);
    values.insert(values.end(), data.begin(), data.end());

    return rs1024_polymod(values) == 1;
}

// ============================================================================
// Feistel Cipher (PBKDF2-HMAC-SHA256)
// ============================================================================

static std::vector<uint8_t> feistel_encrypt(
    const std::vector<uint8_t> &master_secret,
    const std::string &passphrase,
    uint8_t iteration_exponent,
    uint16_t identifier,
    bool extendable)
{
    const size_t half = master_secret.size() / 2;
    const uint32_t iterations = BASE_ITERATION_COUNT << iteration_exponent;

    std::vector<uint8_t> l(master_secret.begin(), master_secret.begin() + half);
    std::vector<uint8_t> r(master_secret.begin() + half, master_secret.end());

    // Salt prefix: "shamir" or "shamir_extendable" + identifier bytes (for non-extendable)
    std::string salt_prefix;

    if (extendable)
    {
        salt_prefix = "shamir_extendable";
    }
    else
    {
        salt_prefix = "shamir";
        salt_prefix += static_cast<char>((identifier >> 8) & 0xff);
        salt_prefix += static_cast<char>(identifier & 0xff);
    }

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;

    for (int round = 0; round < 4; ++round)
    {
        // password = round_byte || passphrase
        std::vector<uint8_t> password(1 + passphrase.size());
        password[0] = static_cast<uint8_t>(round);
        std::memcpy(password.data() + 1, passphrase.data(), passphrase.size());

        // salt = salt_prefix || source_half
        const auto &source = (round % 2 == 0) ? r : l;
        std::vector<uint8_t> salt(salt_prefix.size() + source.size());
        std::memcpy(salt.data(), salt_prefix.data(), salt_prefix.size());
        std::memcpy(salt.data() + salt_prefix.size(), source.data(), source.size());

        // Derive key
        auto &target = (round % 2 == 0) ? l : r;
        std::vector<uint8_t> derived(target.size());

        pbkdf2.DeriveKey(
            derived.data(), derived.size(), 0, password.data(), password.size(), salt.data(), salt.size(), iterations);

        // XOR into target
        for (size_t i = 0; i < target.size(); ++i)
        {
            target[i] ^= derived[i];
        }
    }

    std::vector<uint8_t> result;
    result.insert(result.end(), l.begin(), l.end());
    result.insert(result.end(), r.begin(), r.end());

    return result;
}

static std::vector<uint8_t> feistel_decrypt(
    const std::vector<uint8_t> &encrypted_secret,
    const std::string &passphrase,
    uint8_t iteration_exponent,
    uint16_t identifier,
    bool extendable)
{
    const size_t half = encrypted_secret.size() / 2;
    const uint32_t iterations = BASE_ITERATION_COUNT << iteration_exponent;

    std::vector<uint8_t> l(encrypted_secret.begin(), encrypted_secret.begin() + half);
    std::vector<uint8_t> r(encrypted_secret.begin() + half, encrypted_secret.end());

    std::string salt_prefix;

    if (extendable)
    {
        salt_prefix = "shamir_extendable";
    }
    else
    {
        salt_prefix = "shamir";
        salt_prefix += static_cast<char>((identifier >> 8) & 0xff);
        salt_prefix += static_cast<char>(identifier & 0xff);
    }

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;

    // Reverse order: rounds 3, 2, 1, 0
    for (int round = 3; round >= 0; --round)
    {
        std::vector<uint8_t> password(1 + passphrase.size());
        password[0] = static_cast<uint8_t>(round);
        std::memcpy(password.data() + 1, passphrase.data(), passphrase.size());

        const auto &source = (round % 2 == 0) ? r : l;
        std::vector<uint8_t> salt(salt_prefix.size() + source.size());
        std::memcpy(salt.data(), salt_prefix.data(), salt_prefix.size());
        std::memcpy(salt.data() + salt_prefix.size(), source.data(), source.size());

        auto &target = (round % 2 == 0) ? l : r;
        std::vector<uint8_t> derived(target.size());

        pbkdf2.DeriveKey(
            derived.data(), derived.size(), 0, password.data(), password.size(), salt.data(), salt.size(), iterations);

        for (size_t i = 0; i < target.size(); ++i)
        {
            target[i] ^= derived[i];
        }
    }

    std::vector<uint8_t> result;
    result.insert(result.end(), l.begin(), l.end());
    result.insert(result.end(), r.begin(), r.end());

    return result;
}

// ============================================================================
// Mnemonic Encode/Decode (10-bit word indices <-> bit stream)
// ============================================================================

// Pack share data into 10-bit word indices
static std::vector<uint16_t> share_to_indices(const slip39_share_t &share)
{
    // Build the bit stream: header fields + value bytes
    // We pack everything into a vector of 10-bit words

    // First, construct the header as a 40-bit integer
    uint64_t header = 0;
    header = (header << ID_BITS) | (share.identifier & 0x7fff);
    header = (header << EXTENDABLE_BIT) | (share.extendable ? 1 : 0);
    header = (header << ITERATION_EXP_BITS) | (share.iteration_exponent & 0xf);
    header = (header << GROUP_INDEX_BITS) | (share.group_index & 0xf);
    header = (header << GROUP_THRESHOLD_BITS) | (share.group_threshold & 0xf);
    header = (header << GROUP_COUNT_BITS) | (share.group_count & 0xf);
    header = (header << MEMBER_INDEX_BITS) | (share.member_index & 0xf);
    header = (header << MEMBER_THRESHOLD_BITS) | (share.member_threshold & 0xf);

    // Total bits: HEADER_BITS + value_bytes*8, padded to 10-bit boundary
    const size_t value_bits = share.value.size() * 8;
    const size_t total_bits = HEADER_BITS + value_bits;
    const size_t padding_bits = (RADIX_BITS - (total_bits % RADIX_BITS)) % RADIX_BITS;
    const size_t num_words = (total_bits + padding_bits) / RADIX_BITS;

    // Build bit stream as a vector of bools for simplicity
    std::vector<bool> bits;
    bits.reserve(total_bits + padding_bits);

    // Add header bits (40 bits)
    for (int i = HEADER_BITS - 1; i >= 0; --i)
    {
        bits.push_back((header >> i) & 1);
    }

    // Add value bytes
    for (const auto byte : share.value)
    {
        for (int i = 7; i >= 0; --i)
        {
            bits.push_back((byte >> i) & 1);
        }
    }

    // Add padding
    for (size_t i = 0; i < padding_bits; ++i)
    {
        bits.push_back(false);
    }

    // Convert to 10-bit words
    std::vector<uint16_t> indices(num_words);

    for (size_t w = 0; w < num_words; ++w)
    {
        uint16_t word = 0;

        for (size_t b = 0; b < RADIX_BITS; ++b)
        {
            word = (word << 1) | (bits[w * RADIX_BITS + b] ? 1 : 0);
        }

        indices[w] = word;
    }

    return indices;
}

// Decode 10-bit word indices back to share data
static slip39_share_t indices_to_share(const std::vector<uint16_t> &indices, size_t value_byte_count)
{
    // Convert indices to bit stream
    std::vector<bool> bits;
    bits.reserve(indices.size() * RADIX_BITS);

    for (const auto idx : indices)
    {
        for (int i = RADIX_BITS - 1; i >= 0; --i)
        {
            bits.push_back((idx >> i) & 1);
        }
    }

    // Extract header (40 bits)
    uint64_t header = 0;

    for (size_t i = 0; i < HEADER_BITS; ++i)
    {
        header = (header << 1) | (bits[i] ? 1 : 0);
    }

    slip39_share_t share;
    share.member_threshold = static_cast<uint8_t>(header & 0xf);
    header >>= MEMBER_THRESHOLD_BITS;
    share.member_index = static_cast<uint8_t>(header & 0xf);
    header >>= MEMBER_INDEX_BITS;
    share.group_count = static_cast<uint8_t>(header & 0xf);
    header >>= GROUP_COUNT_BITS;
    share.group_threshold = static_cast<uint8_t>(header & 0xf);
    header >>= GROUP_THRESHOLD_BITS;
    share.group_index = static_cast<uint8_t>(header & 0xf);
    header >>= GROUP_INDEX_BITS;
    share.iteration_exponent = static_cast<uint8_t>(header & 0xf);
    header >>= ITERATION_EXP_BITS;
    share.extendable = (header & 1) != 0;
    header >>= EXTENDABLE_BIT;
    share.identifier = static_cast<uint16_t>(header & 0x7fff);

    // Extract value bytes
    share.value.resize(value_byte_count);

    for (size_t i = 0; i < value_byte_count; ++i)
    {
        uint8_t byte = 0;

        for (size_t b = 0; b < 8; ++b)
        {
            const size_t bit_pos = HEADER_BITS + i * 8 + b;

            byte = (byte << 1) | (bits[bit_pos] ? 1 : 0);
        }

        share.value[i] = byte;
    }

    return share;
}

// Compute the expected value byte count from total word count
static size_t value_byte_count_from_word_count(size_t word_count)
{
    // total_bits = word_count * 10 (excluding checksum)
    // header_bits = 40
    // value_bits = total_bits - header_bits - padding
    // For 128-bit: 20 words total, 17 data words -> 170 bits - 40 = 130 bits -> 16 bytes (2 padding bits)
    // For 256-bit: 33 words total, 30 data words -> 300 bits - 40 = 260 bits -> 32 bytes (4 padding bits)
    const size_t data_words = word_count - CHECKSUM_WORDS;
    const size_t total_data_bits = data_words * RADIX_BITS;

    if (total_data_bits <= HEADER_BITS)
    {
        throw std::invalid_argument("Share too short");
    }

    const size_t value_bits = total_data_bits - HEADER_BITS;

    // Round down to nearest byte
    return value_bits / 8;
}

// Encode share to mnemonic words
static std::vector<std::string> encode_share(const slip39_share_t &share)
{
    const auto words = Crypto::Mnemonics::SLIP39::English::word_list();

    auto data_indices = share_to_indices(share);

    // Add RS1024 checksum
    const auto checksum = rs1024_create_checksum(data_indices, share.extendable);
    data_indices.insert(data_indices.end(), checksum.begin(), checksum.end());

    std::vector<std::string> result;
    result.reserve(data_indices.size());

    for (const auto idx : data_indices)
    {
        if (idx >= words.size())
        {
            throw std::runtime_error("Word index out of range");
        }

        result.push_back(words[idx]);
    }

    return result;
}

// Decode mnemonic words to share
static slip39_share_t decode_share(const std::vector<std::string> &mnemonic)
{
    const auto words = Crypto::Mnemonics::SLIP39::English::word_list();

    // Build word -> index map
    std::map<std::string, uint16_t> word_map;

    for (uint16_t i = 0; i < words.size(); ++i)
    {
        word_map[words[i]] = i;
    }

    // Convert words to indices
    std::vector<uint16_t> indices;
    indices.reserve(mnemonic.size());

    for (const auto &word : mnemonic)
    {
        auto it = word_map.find(word);

        if (it == word_map.end())
        {
            throw std::invalid_argument("Invalid SLIP-39 word: " + word);
        }

        indices.push_back(it->second);
    }

    // We need to determine extendable flag before verifying checksum
    // Extract it from the header first
    const size_t value_bytes = value_byte_count_from_word_count(mnemonic.size());
    auto share = indices_to_share(std::vector<uint16_t>(indices.begin(), indices.end() - CHECKSUM_WORDS), value_bytes);

    // Verify RS1024 checksum
    if (!rs1024_verify_checksum(indices, share.extendable))
    {
        throw std::runtime_error("SLIP-39 share checksum verification failed");
    }

    return share;
}

// ============================================================================
// Public API
// ============================================================================

namespace Crypto::Mnemonics::Shamir
{
    std::vector<std::vector<std::string>> split(
        const crypto_entropy_t &entropy,
        size_t threshold,
        size_t total_shares,
        const std::string &passphrase,
        uint8_t iteration_exponent,
        bool extendable)
    {
        gf256_init_tables();

        if (threshold < 1 || threshold > total_shares)
        {
            throw std::invalid_argument("Threshold must satisfy 1 <= T <= N");
        }

        if (total_shares > MAX_SHARE_COUNT)
        {
            throw std::invalid_argument("Total shares must be <= 16");
        }

        // Determine entropy size
        const auto entropy_bytes = entropy.serialize();
        const bool is_128 =
            entropy.empty()
            || std::all_of(entropy_bytes.begin() + 16, entropy_bytes.end(), [](uint8_t b) { return b == 0; });
        const size_t secret_len = is_128 ? 16 : 32;

        if (secret_len < MIN_STRENGTH_BITS / 8)
        {
            throw std::invalid_argument("Entropy too short");
        }

        if (secret_len % 2 != 0)
        {
            throw std::invalid_argument("Secret length must be even");
        }

        std::vector<uint8_t> master_secret(entropy_bytes.begin(), entropy_bytes.begin() + secret_len);

        // Generate random identifier (15 bits)
        uint16_t identifier = 0;
        uint8_t id_bytes[2];
        random_bytes(2, id_bytes);
        identifier = static_cast<uint16_t>((id_bytes[0] << 8 | id_bytes[1]) & 0x7fff);

        // Encrypt master secret with Feistel cipher
        auto encrypted_secret = feistel_encrypt(master_secret, passphrase, iteration_exponent, identifier, extendable);

        // Split encrypted secret using Shamir SSS
        auto shares = shamir_split(encrypted_secret, threshold, total_shares);

        // Encode each share as mnemonic words
        std::vector<std::vector<std::string>> result;
        result.reserve(total_shares);

        for (size_t i = 0; i < total_shares; ++i)
        {
            slip39_share_t share;
            share.identifier = identifier;
            share.extendable = extendable;
            share.iteration_exponent = iteration_exponent;
            share.group_index = 0;
            share.group_threshold = 0; // encoded as threshold-1, single group = 0
            share.group_count = 0; // encoded as count-1, single group = 0
            share.member_index = shares[i].first;
            share.member_threshold = static_cast<uint8_t>(threshold - 1); // encoded as threshold-1
            share.value = shares[i].second;

            result.push_back(encode_share(share));
        }

        return result;
    }

    crypto_entropy_t combine(const std::vector<std::vector<std::string>> &shares, const std::string &passphrase)
    {
        gf256_init_tables();

        if (shares.empty())
        {
            throw std::invalid_argument("No shares provided");
        }

        // Decode all shares
        std::vector<slip39_share_t> decoded_shares;
        decoded_shares.reserve(shares.size());

        for (const auto &mnemonic : shares)
        {
            decoded_shares.push_back(decode_share(mnemonic));
        }

        // Verify all shares have same parameters
        const auto &first = decoded_shares[0];

        for (size_t i = 1; i < decoded_shares.size(); ++i)
        {
            const auto &s = decoded_shares[i];

            if (s.identifier != first.identifier)
            {
                throw std::invalid_argument("Shares have different identifiers");
            }

            if (s.extendable != first.extendable)
            {
                throw std::invalid_argument("Shares have different extendable flags");
            }

            if (s.iteration_exponent != first.iteration_exponent)
            {
                throw std::invalid_argument("Shares have different iteration exponents");
            }

            if (s.group_threshold != first.group_threshold || s.group_count != first.group_count)
            {
                throw std::invalid_argument("Shares have different group parameters");
            }

            if (s.member_threshold != first.member_threshold)
            {
                throw std::invalid_argument("Shares have different member thresholds");
            }
        }

        const size_t threshold = first.member_threshold + 1; // decode from stored value

        if (decoded_shares.size() < threshold)
        {
            throw std::invalid_argument(
                "Not enough shares: need " + std::to_string(threshold) + ", got "
                + std::to_string(decoded_shares.size()));
        }

        // Check for duplicate member indices
        std::vector<uint8_t> member_indices;

        for (const auto &s : decoded_shares)
        {
            if (std::find(member_indices.begin(), member_indices.end(), s.member_index) != member_indices.end())
            {
                throw std::invalid_argument("Duplicate share detected");
            }

            member_indices.push_back(s.member_index);
        }

        // Collect x coordinates and values for Shamir recovery
        std::vector<uint8_t> x_coords;
        std::vector<std::vector<uint8_t>> share_values;

        for (const auto &s : decoded_shares)
        {
            x_coords.push_back(s.member_index);
            share_values.push_back(s.value);
        }

        // Recover encrypted secret
        auto encrypted_secret = shamir_combine(x_coords, share_values, threshold);

        // Decrypt with Feistel cipher
        auto master_secret =
            feistel_decrypt(encrypted_secret, passphrase, first.iteration_exponent, first.identifier, first.extendable);

        // Convert to crypto_entropy_t (pad to 32 bytes if 128-bit)
        std::vector<unsigned char> entropy_bytes(32, 0);
        std::memcpy(entropy_bytes.data(), master_secret.data(), master_secret.size());

        return crypto_entropy_t(entropy_bytes);
    }

    bool validate_share(const std::vector<std::string> &words)
    {
        try
        {
            decode_share(words);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    std::vector<unsigned char>
        derive_seed(const crypto_entropy_t &entropy, const std::string &passphrase, bool extendable)
    {
        const auto entropy_bytes = entropy.serialize();
        const bool is_128 =
            std::all_of(entropy_bytes.begin() + 16, entropy_bytes.end(), [](uint8_t b) { return b == 0; });
        const size_t secret_len = is_128 ? 16 : 32;

        const std::string salt_prefix = extendable ? "shamir_extendable" : "shamir";
        const std::string salt = salt_prefix + passphrase;

        std::vector<unsigned char> seed(64);

        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;

        pbkdf2.DeriveKey(
            seed.data(),
            seed.size(),
            0,
            entropy_bytes.data(),
            secret_len,
            reinterpret_cast<const CryptoPP::byte *>(salt.data()),
            salt.size(),
            BASE_ITERATION_COUNT);

        return seed;
    }

    std::vector<std::string> word_list()
    {
        return Crypto::Mnemonics::SLIP39::English::word_list();
    }
} // namespace Crypto::Mnemonics::Shamir
