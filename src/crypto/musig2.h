#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// MuSig2 -- n-of-n Schnorr multi-signature scheme.
//
// Implements a simplified MuSig2 protocol producing 64-byte Schnorr
// signatures indistinguishable from single-signer BIP-340 signatures.
//
// Protocol overview:
//   1.  Key aggregation:  all signers exchange x-only pubkeys; the
//       aggregated key Q = sum(ai * Pi) is computed deterministically.
//   2.  Nonce generation: each signer produces two secret/public nonce
//       pairs (k1, R1) and (k2, R2).
//   3.  Nonce aggregation: public nonces are summed component-wise.
//   4.  Partial signing:  each signer computes a partial signature
//       using their secret key, secret nonce, and the aggregated state.
//   5.  Aggregation: partial signatures are summed modulo the curve
//       order to yield the final 64-byte (R || s) Schnorr signature.
//
// SECURITY: Secret nonces (MuSig2SecNonce) MUST be used exactly once
//           and securely erased after partial signing.
// ---------------------------------------------------------------------------

#include "core/types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace crypto {

// ===================================================================
// Key aggregation
// ===================================================================

/// Result of MuSig2 key aggregation: the combined x-only public key
/// and per-signer coefficients used throughout the signing session.
struct MuSig2KeyAgg {
    std::array<uint8_t, 32> agg_pubkey;                    // x-only
    std::vector<std::array<uint8_t, 32>> key_coefficients;  // per-signer
};

/// Aggregate a set of x-only (32-byte) public keys into a single
/// combined key.  The pubkeys are sorted lexicographically internally;
/// each signer receives a deterministic coefficient ai = H(L || Pi)
/// where L = H(P1 || P2 || ... || Pn) over the sorted list.
///
/// @pre  pubkeys.size() >= 2.
/// @throws std::invalid_argument if fewer than 2 keys are supplied.
[[nodiscard]] MuSig2KeyAgg musig2_key_agg(
    const std::vector<std::array<uint8_t, 32>>& pubkeys);

// ===================================================================
// Nonce types
// ===================================================================

/// Per-signer secret nonce pair.  MUST be kept private and used
/// exactly once for a single signing session.
struct MuSig2SecNonce {
    std::array<uint8_t, 32> k1;
    std::array<uint8_t, 32> k2;
};

/// Per-signer public nonce pair (SEC1 compressed points, 33 bytes).
struct MuSig2PubNonce {
    std::array<uint8_t, 33> R1;
    std::array<uint8_t, 33> R2;
};

/// Aggregated public nonce (two compressed points).
struct MuSig2AggNonce {
    std::array<uint8_t, 33> R_agg1;
    std::array<uint8_t, 33> R_agg2;
};

// ===================================================================
// Nonce generation and aggregation
// ===================================================================

/// Generate a deterministic secret/public nonce pair for a signing
/// session.  Derivation uses HMAC-Keccak256 keyed by the secret
/// scalar, mixed with the aggregated pubkey and message.
///
/// @param secret_key   32-byte secret scalar of this signer.
/// @param agg_pubkey   32-byte aggregated x-only public key.
/// @param msg          Message hash being signed.
[[nodiscard]] std::pair<MuSig2SecNonce, MuSig2PubNonce> musig2_nonce_gen(
    std::span<const uint8_t, 32> secret_key,
    std::span<const uint8_t, 32> agg_pubkey,
    const core::uint256& msg);

/// Sum the per-signer public nonces component-wise to produce the
/// aggregated nonce.
///
/// @pre  pub_nonces.size() >= 2.
[[nodiscard]] MuSig2AggNonce musig2_nonce_agg(
    const std::vector<MuSig2PubNonce>& pub_nonces);

// ===================================================================
// Partial signing and verification
// ===================================================================

/// Produce a 32-byte partial signature for this signer.
///
/// @param sec_nonce    Secret nonce pair (consumed -- caller should
///                     erase after this call).
/// @param secret_key   32-byte secret scalar.
/// @param key_agg      Key aggregation context.
/// @param agg_nonce    Aggregated public nonce.
/// @param signer_index Index of this signer in the *original*
///                     (pre-sort) pubkey vector passed to key_agg.
/// @param msg          Message hash being signed.
[[nodiscard]] std::array<uint8_t, 32> musig2_partial_sign(
    const MuSig2SecNonce& sec_nonce,
    std::span<const uint8_t, 32> secret_key,
    const MuSig2KeyAgg& key_agg,
    const MuSig2AggNonce& agg_nonce,
    size_t signer_index,
    const core::uint256& msg);

/// Verify a single partial signature from a specific signer.
[[nodiscard]] bool musig2_partial_verify(
    std::span<const uint8_t, 32> partial_sig,
    const MuSig2PubNonce& pub_nonce,
    std::span<const uint8_t, 32> pubkey,
    const MuSig2KeyAgg& key_agg,
    const MuSig2AggNonce& agg_nonce,
    size_t signer_index,
    const core::uint256& msg);

/// Aggregate all partial signatures into the final 64-byte Schnorr
/// signature (R_x || s), where R is the final nonce point and s is
/// the sum of all partial s-values modulo the curve order.
[[nodiscard]] std::array<uint8_t, 64> musig2_partial_sig_agg(
    const std::vector<std::array<uint8_t, 32>>& partial_sigs,
    const MuSig2AggNonce& agg_nonce,
    const core::uint256& msg);

}  // namespace crypto
