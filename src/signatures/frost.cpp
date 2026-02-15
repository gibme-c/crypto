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
 * @file frost.cpp
 * @brief FROST threshold signature: Feldman VSS DKG + 2-round signing + aggregation.
 */

#include <crypto_constants.h>
#include <helpers/scalar_transcript_t.h>
#include <signatures/frost.h>

#include <algorithm>
#include <set>
#include <stdexcept>

namespace Crypto::FROST
{
    /**
     * Compute Lagrange coefficient for participant `id` given the set of signer identifiers.
     * lambda_i = product( x_j / (x_j - x_i) ) for j != i
     */
    static crypto_scalar_t lagrange_coefficient(size_t id, const std::vector<size_t> &signer_ids)
    {
        auto result = Crypto::ONE;

        const auto x_i = crypto_scalar_t(id);

        for (const auto &other_id : signer_ids)
        {
            if (other_id == id)
            {
                continue;
            }

            const auto x_j = crypto_scalar_t(other_id);

            // numerator: x_j, denominator: x_j - x_i
            result = result * (x_j * (x_j - x_i).invert());
        }

        return result;
    }

    /**
     * Compute binding factor rho for a participant.
     */
    static crypto_scalar_t compute_binding_factor(
        size_t identifier,
        const crypto_hash_t &message_digest,
        const std::vector<crypto_frost_nonce_commitment_t> &all_commitments)
    {
        scalar_transcript_t transcript(FROST_DOMAIN_0);
        transcript.update(message_digest);
        transcript.update(crypto_scalar_t(identifier));

        // Include all commitments in the binding factor
        for (const auto &commitment : all_commitments)
        {
            transcript.update(crypto_scalar_t(commitment.identifier));
            transcript.update(commitment.hiding);
            transcript.update(commitment.binding);
        }

        return transcript.challenge();
    }

    /**
     * Compute group commitment R = sum(D_i + rho_i * E_i) for all signers.
     */
    static crypto_point_t compute_group_commitment(
        const crypto_hash_t &message_digest,
        const std::vector<crypto_frost_nonce_commitment_t> &all_commitments)
    {
        auto R = Crypto::Z;

        for (const auto &commitment : all_commitments)
        {
            const auto rho = compute_binding_factor(commitment.identifier, message_digest, all_commitments);

            R = R + commitment.hiding + (rho * commitment.binding);
        }

        return R;
    }

    /**
     * Compute the Schnorr challenge c = H(FROST_DOMAIN_0, R, PK, message).
     */
    static crypto_scalar_t compute_challenge(
        const crypto_point_t &group_commitment,
        const crypto_point_t &group_public_key,
        const crypto_hash_t &message_digest)
    {
        scalar_transcript_t transcript(FROST_DOMAIN_0, group_commitment, group_public_key, message_digest);

        return transcript.challenge();
    }

    std::tuple<std::vector<crypto_frost_secret_share_t>, crypto_point_vector_t>
        dkg_part1(size_t identifier, size_t max_signers, size_t min_signers)
    {
        if (identifier == 0)
        {
            throw std::invalid_argument("FROST identifier must be non-zero");
        }

        if (min_signers < 2 || min_signers > max_signers)
        {
            throw std::invalid_argument("FROST requires 2 <= min_signers <= max_signers");
        }

        // Generate random polynomial of degree (min_signers - 1)
        // a_0 is the secret share of the group key, a_1..a_{t-1} are random
        std::vector<crypto_scalar_t> coefficients(min_signers);

        for (size_t k = 0; k < min_signers; ++k)
        {
            coefficients[k] = crypto_scalar_t::random();
        }

        // VSS commitments: A_k = a_k * G for k = 0..t-1
        crypto_point_vector_t commitments(min_signers);

        for (size_t k = 0; k < min_signers; ++k)
        {
            commitments[k] = coefficients[k] * Crypto::G;
        }

        // Evaluate polynomial at each participant index: f(i) = sum(a_k * i^k)
        std::vector<crypto_frost_secret_share_t> shares(max_signers);

        for (size_t i = 0; i < max_signers; ++i)
        {
            const auto x = crypto_scalar_t(i + 1); // identifiers are 1-based

            auto share_value = crypto_scalar_t();

            auto x_pow = Crypto::ONE; // x^0 = 1

            for (size_t k = 0; k < min_signers; ++k)
            {
                share_value = share_value + (coefficients[k] * x_pow);

                x_pow = x_pow * x;
            }

            shares[i] = crypto_frost_secret_share_t(i + 1, share_value);
        }

        // Erase secret polynomial coefficients
        for (auto &coeff : coefficients)
        {
            coeff = crypto_scalar_t();
        }

        return {shares, commitments};
    }

    bool dkg_verify_share(
        const crypto_frost_secret_share_t &share,
        const crypto_point_vector_t &sender_commitments)
    {
        if (share.identifier == 0 || sender_commitments.size() == 0)
        {
            return false;
        }

        // Verify: f(i) * G == sum(i^k * A_k) for k = 0..t-1
        const auto lhs = share.value * Crypto::G;

        const auto x = crypto_scalar_t(share.identifier);

        auto rhs = Crypto::Z;

        auto x_pow = Crypto::ONE;

        for (size_t k = 0; k < sender_commitments.size(); ++k)
        {
            rhs = rhs + (x_pow * sender_commitments[k]);

            x_pow = x_pow * x;
        }

        return lhs == rhs;
    }

    crypto_frost_key_package_t dkg_part3(
        size_t identifier,
        const std::vector<crypto_frost_secret_share_t> &received_shares,
        const std::vector<crypto_point_vector_t> &all_commitments)
    {
        if (identifier == 0)
        {
            throw std::invalid_argument("FROST identifier must be non-zero");
        }

        if (received_shares.empty() || all_commitments.empty())
        {
            throw std::invalid_argument("FROST DKG part 3 requires received shares and commitments");
        }

        // signing_share = sum of all shares received for this participant
        auto signing_share = crypto_scalar_t();

        for (const auto &share : received_shares)
        {
            signing_share = signing_share + share.value;
        }

        // verifying_share = signing_share * G
        const auto verifying_share = signing_share * Crypto::G;

        // group_public_key = sum of all participants' A_{j,0} (free term commitments)
        auto group_public_key = Crypto::Z;

        for (const auto &commitments : all_commitments)
        {
            if (commitments.size() == 0)
            {
                throw std::invalid_argument("Empty commitment vector in DKG part 3");
            }

            group_public_key = group_public_key + commitments[0];
        }

        const auto min_signers = all_commitments[0].size();

        return {identifier, signing_share, verifying_share, group_public_key, min_signers};
    }

    crypto_frost_public_key_package_t build_public_key_package(
        size_t max_signers,
        const std::vector<crypto_point_vector_t> &all_commitments)
    {
        // group_public_key = sum of A_{j,0}
        auto group_public_key = Crypto::Z;

        for (const auto &commitments : all_commitments)
        {
            group_public_key = group_public_key + commitments[0];
        }

        // Compute each participant's verifying share: V_i = sum_j(sum_k(i^k * A_{j,k}))
        std::vector<std::pair<size_t, crypto_point_t>> verifying_shares(max_signers);

        for (size_t i = 0; i < max_signers; ++i)
        {
            const auto id = i + 1;
            const auto x = crypto_scalar_t(id);

            auto share_point = Crypto::Z;

            for (const auto &commitments : all_commitments)
            {
                auto x_pow = Crypto::ONE;

                for (size_t k = 0; k < commitments.size(); ++k)
                {
                    share_point = share_point + (x_pow * commitments[k]);

                    x_pow = x_pow * x;
                }
            }

            verifying_shares[i] = {id, share_point};
        }

        return {group_public_key, verifying_shares};
    }

    std::tuple<crypto_frost_nonce_t, crypto_frost_nonce_commitment_t>
        round1_commit(size_t identifier)
    {
        if (identifier == 0)
        {
            throw std::invalid_argument("FROST identifier must be non-zero");
        }

        // Generate random nonces via scalar transcript (domain-separated, entropy-mixed)
        scalar_transcript_t hiding_transcript(FROST_DOMAIN_1, crypto_scalar_t(identifier), crypto_scalar_t::random());

        const auto hiding_nonce = hiding_transcript.challenge();

        scalar_transcript_t binding_transcript(FROST_DOMAIN_1, crypto_scalar_t(identifier), crypto_scalar_t::random());

        const auto binding_nonce = binding_transcript.challenge();

        const auto hiding_point = hiding_nonce * Crypto::G;
        const auto binding_point = binding_nonce * Crypto::G;

        return {
            {hiding_nonce, binding_nonce},
            {identifier, hiding_point, binding_point}
        };
    }

    crypto_frost_signature_share_t round2_sign(
        const crypto_hash_t &message_digest,
        const crypto_frost_key_package_t &key_package,
        const crypto_frost_nonce_t &signer_nonces,
        const std::vector<crypto_frost_nonce_commitment_t> &all_commitments)
    {
        SCALAR_NZ_OR_THROW(key_package.signing_share);

        // Check for duplicate identifiers
        std::set<size_t> seen_ids;

        for (const auto &commitment : all_commitments)
        {
            if (commitment.identifier == 0)
            {
                throw std::invalid_argument("FROST identifier must be non-zero");
            }

            if (!seen_ids.insert(commitment.identifier).second)
            {
                throw std::invalid_argument("Duplicate participant identifier in FROST signing");
            }
        }

        // Collect signer IDs for Lagrange computation
        std::vector<size_t> signer_ids;
        signer_ids.reserve(all_commitments.size());

        for (const auto &commitment : all_commitments)
        {
            signer_ids.push_back(commitment.identifier);
        }

        // Compute binding factor for this signer
        const auto rho = compute_binding_factor(key_package.identifier, message_digest, all_commitments);

        // Compute group commitment
        const auto R = compute_group_commitment(message_digest, all_commitments);

        // Compute challenge
        const auto c = compute_challenge(R, key_package.group_public_key, message_digest);

        // Compute Lagrange coefficient
        const auto lambda = lagrange_coefficient(key_package.identifier, signer_ids);

        // Signature share: z_i = d_i + e_i * rho_i + lambda_i * s_i * c
        auto z = signer_nonces.hiding_nonce + (signer_nonces.binding_nonce * rho) + (lambda * key_package.signing_share * c);

        return {key_package.identifier, z};
    }

    std::tuple<bool, crypto_signature_t> aggregate(
        const crypto_hash_t &message_digest,
        const std::vector<crypto_frost_signature_share_t> &signature_shares,
        const std::vector<crypto_frost_nonce_commitment_t> &all_commitments,
        const crypto_frost_public_key_package_t &public_key_package)
    {
        crypto_signature_t empty_sig;

        if (signature_shares.empty() || all_commitments.empty())
        {
            return {false, empty_sig};
        }

        // Collect signer IDs
        std::vector<size_t> signer_ids;
        signer_ids.reserve(all_commitments.size());

        for (const auto &commitment : all_commitments)
        {
            signer_ids.push_back(commitment.identifier);
        }

        // Compute group commitment
        const auto R = compute_group_commitment(message_digest, all_commitments);

        // Compute challenge
        const auto c = compute_challenge(R, public_key_package.group_public_key, message_digest);

        // Verify each signature share individually: z_i*G == D_i + rho_i*E_i + c*lambda_i*V_i
        for (const auto &sig_share : signature_shares)
        {
            // Find commitment for this signer
            const crypto_frost_nonce_commitment_t *signer_commitment = nullptr;

            for (const auto &commitment : all_commitments)
            {
                if (commitment.identifier == sig_share.identifier)
                {
                    signer_commitment = &commitment;

                    break;
                }
            }

            if (signer_commitment == nullptr)
            {
                return {false, empty_sig};
            }

            // Find verifying share for this signer
            const crypto_point_t *verifying_share = nullptr;

            for (const auto &[id, pt] : public_key_package.verifying_shares)
            {
                if (id == sig_share.identifier)
                {
                    verifying_share = &pt;

                    break;
                }
            }

            if (verifying_share == nullptr)
            {
                return {false, empty_sig};
            }

            const auto rho = compute_binding_factor(sig_share.identifier, message_digest, all_commitments);
            const auto lambda = lagrange_coefficient(sig_share.identifier, signer_ids);

            const auto lhs = sig_share.share * Crypto::G;
            const auto rhs = signer_commitment->hiding + (rho * signer_commitment->binding) + (c * lambda * (*verifying_share));

            if (!(lhs == rhs))
            {
                return {false, empty_sig};
            }
        }

        // Aggregate: z = sum(z_i)
        auto z = crypto_scalar_t();

        for (const auto &sig_share : signature_shares)
        {
            z = z + sig_share.share;
        }

        // Final signature: (R, z) encoded as a standard crypto_signature_t
        // Store R point bytes in LR.L (as scalar bytes) and z in LR.R
        // We follow the same convention as the library's Schnorr signature:
        // LR.L = challenge c, LR.R = response such that R = LR.R*G + LR.L*PK
        // So: LR.L = c, LR.R = z - c*... no, let's use the standard approach.
        // The library's verify: point = c*PK + r*G, then c' = H(domain, msg, PK, point), check c==c'
        // For FROST: we have z*G = R + c*PK, so R = z*G - c*PK
        // This means: point = (-c)*PK + z*G, and we need c' = H(FROST_DOMAIN_0, point, PK, msg)
        // But the library's check_signature uses SIGNATURE_DOMAIN_0, not FROST_DOMAIN_0.
        // So we can't use check_signature directly. We store (c, z-c) format but that doesn't work either.
        // Per the plan: "Final signature: standard crypto_signature_t (64 bytes)"
        // and "Verification: Reuse Crypto::Signature::check_signature"
        // But the domain separation makes this impossible to reuse directly.
        //
        // Let's store in the library's Schnorr format:
        // LR.L = c (challenge), LR.R = z - c (response, so that LR.R * G + LR.L * PK = R)
        // Wait: the library verify does point = c*PK + r*G, then hashes (SIGNATURE_DOMAIN_0, msg, PK, point).
        // If we use FROST_DOMAIN_0 the challenges won't match.
        //
        // The cleanest approach: store as (c, r) where r = z such that the aggregate verifier
        // can reconstruct R from z and c. But then we need a custom verify.
        //
        // Actually, looking at the library format more carefully:
        // generate_signature: c = H(SIGNATURE_DOMAIN_0, msg, PK, alpha*G), r = alpha - c*sk
        // check_signature: point = c*PK + r*G, c' = H(SIGNATURE_DOMAIN_0, msg, PK, point), check c==c'
        // => point = c*PK + (alpha - c*sk)*G = c*sk*G + alpha*G - c*sk*G = alpha*G = R. Good.
        //
        // For FROST we have: c = H(FROST_DOMAIN_0, R, PK, msg) and z*G = R + c*PK
        // => R = z*G - c*PK
        // If we set LR.L = c, LR.R = z, then verify would need:
        //   R = z*G - c*PK (different sign convention from library!)
        // Library does: point = c*PK + r*G, but FROST needs: point = z*G - c*PK = z*G + (-c)*PK
        // These don't match. So let's convert:
        //   Let r_lib = z, c_lib = -c. Then point = c_lib*PK + r_lib*G = (-c)*PK + z*G = R. Match!
        //   But then check would compute c' = H(SIGNATURE_DOMAIN_0, msg, PK, R) != H(FROST_DOMAIN_0, R, PK, msg)
        // Still different because of different domain and argument order.
        //
        // Conclusion: We cannot directly reuse check_signature without modifying the domain.
        // The plan says to reuse it, but mathematically it requires the same domain.
        // Best approach: generate the FROST signature using SIGNATURE_DOMAIN_0 so it's compatible.

        // Recompute challenge using SIGNATURE_DOMAIN_0 for compatibility with check_signature
        scalar_transcript_t sig_transcript(SIGNATURE_DOMAIN_0, message_digest, public_key_package.group_public_key, R);

        const auto sig_c = sig_transcript.challenge();

        // The library's format: LR.L = c, LR.R = alpha - c*sk
        // We need: point = c*PK + r*G = R => r = z - c_sig * group_sk (but we don't have group_sk!)
        // Actually: R = z*G - c*PK (from FROST equation)
        // Library verify: point = c_sig*PK + r*G
        // We need: c_sig*PK + r*G = R = z*G - c*PK
        // => r*G = z*G - c*PK - c_sig*PK = z*G - (c + c_sig)*PK
        // This doesn't simplify nicely.
        //
        // The simplest and most correct approach: just store R and z, and verify
        // by checking z*G == R + c*PK. The user calls a FROST-specific verify or
        // we make aggregate return a bool indicating success.
        // Since aggregate already verifies, just return the raw (R, z) pair.

        crypto_signature_t signature;
        signature.LR.L = crypto_scalar_t(R.serialize());
        signature.LR.R = z;

        // Final verification: z*G == R + c*PK
        const auto lhs = z * Crypto::G;
        const auto rhs = R + (c * public_key_package.group_public_key);

        if (!(lhs == rhs))
        {
            return {false, empty_sig};
        }

        return {true, signature};
    }
} // namespace Crypto::FROST
