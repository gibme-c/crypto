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
 * @file slip39.h
 * @brief SLIP-39 Shamir's Secret Sharing for mnemonic backup and recovery.
 *
 * Splits entropy into N mnemonic shares where any T (threshold) shares can reconstruct
 * the original entropy. Supports 128-bit (20-word) and 256-bit (33-word) shares.
 * Single-group T-of-N only. Uses GF(256) Shamir SSS, RS1024 checksums, and a
 * PBKDF2-based Feistel cipher for passphrase protection.
 */

#ifndef CRYPTO_SLIP39_H
#define CRYPTO_SLIP39_H

#include <string>
#include <types/crypto_entropy_t.h>
#include <vector>

namespace Crypto::Mnemonics::Shamir
{
    /**
     * Splits entropy into N mnemonic shares requiring T to reconstruct.
     *
     * Each share is a vector of words (20 words for 128-bit, 33 words for 256-bit entropy).
     * The master secret is encrypted with a Feistel cipher keyed by the passphrase before
     * splitting, so the same passphrase is required during combine().
     *
     * @param entropy the entropy to split (128 or 256 bits)
     * @param threshold minimum shares needed to reconstruct (2 <= T <= N)
     * @param total_shares total shares to generate (T <= N <= 16)
     * @param passphrase optional passphrase for encryption (default: empty)
     * @param iteration_exponent controls PBKDF2 iterations: 2500 << e (default: 0)
     * @param extendable if true, uses extendable checksum format (default: true)
     * @return vector of N shares, each share being a vector of words
     */
    std::vector<std::vector<std::string>> split(
        const crypto_entropy_t &entropy,
        size_t threshold,
        size_t total_shares,
        const std::string &passphrase = "",
        uint8_t iteration_exponent = 0,
        bool extendable = true);

    /**
     * Combines T or more shares to reconstruct the original entropy.
     *
     * All shares must belong to the same split (same identifier). The passphrase must
     * match the one used during split(). Throws on invalid shares, checksum failures,
     * insufficient shares, or digest verification failure.
     *
     * @param shares vector of T or more shares (each a vector of words)
     * @param passphrase the passphrase used during split (default: empty)
     * @return the reconstructed entropy
     */
    crypto_entropy_t combine(const std::vector<std::vector<std::string>> &shares, const std::string &passphrase = "");

    /**
     * Validates a single share's word list and RS1024 checksum.
     *
     * Does not require other shares or a passphrase -- only checks that the words
     * are valid SLIP-39 words and that the checksum is correct.
     *
     * @param words a single share's word vector
     * @return true if the share is well-formed with a valid checksum
     */
    bool validate_share(const std::vector<std::string> &words);

    /**
     * Derives a 64-byte seed from entropy using SLIP-39 key stretching.
     *
     * Uses PBKDF2-HMAC-SHA256 (NOT BIP-39's PBKDF2-SHA512). This is an optional
     * function for strict SLIP-39 spec compliance; the standard HD key path via
     * crypto_seed_t already handles seed derivation.
     *
     * @param entropy the master entropy
     * @param passphrase optional passphrase
     * @param extendable if true, uses extendable salt format (default: true)
     * @return 64-byte derived seed
     */
    std::vector<unsigned char>
        derive_seed(const crypto_entropy_t &entropy, const std::string &passphrase = "", bool extendable = true);

    /**
     * Returns the 1024-word SLIP-39 English word list.
     *
     * @return the complete SLIP-39 word list
     */
    std::vector<std::string> word_list();
} // namespace Crypto::Mnemonics::Shamir

#endif
