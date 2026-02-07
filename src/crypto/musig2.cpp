// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/musig2.h"
#include "crypto/hash.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>
#include <numeric>
#include <stdexcept>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

namespace crypto {

// ===================================================================
// RAII wrappers for OpenSSL types
// ===================================================================

namespace {

struct BN_CTX_Deleter {
    void operator()(BN_CTX* p) const { BN_CTX_free(p); }
};
struct BN_Deleter {
    void operator()(BIGNUM* p) const { BN_free(p); }
};
struct EC_GROUP_Deleter {
    void operator()(EC_GROUP* p) const { EC_GROUP_free(p); }
};
struct EC_POINT_Deleter {
    void operator()(EC_POINT* p) const { EC_POINT_free(p); }
};

using BN_CTX_Ptr   = std::unique_ptr<BN_CTX, BN_CTX_Deleter>;
using BN_Ptr       = std::unique_ptr<BIGNUM, BN_Deleter>;
using EC_GROUP_Ptr = std::unique_ptr<EC_GROUP, EC_GROUP_Deleter>;
using EC_POINT_Ptr = std::unique_ptr<EC_POINT, EC_POINT_Deleter>;

// ===================================================================
// Curve helpers
// ===================================================================

/// Create a fresh secp256k1 group.  Thread-safe (no shared state).
EC_GROUP_Ptr make_group() {
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!g) {
        throw std::runtime_error(
            "musig2: failed to create secp256k1 group");
    }
    return EC_GROUP_Ptr(g);
}

/// Return the curve order n.
BN_Ptr get_order(const EC_GROUP* group, BN_CTX* ctx) {
    BN_Ptr order(BN_new());
    if (!order || !EC_GROUP_get_order(group, order.get(), ctx)) {
        throw std::runtime_error(
            "musig2: failed to get curve order");
    }
    return order;
}

/// Create an EC_POINT on the given group.
EC_POINT_Ptr make_point(const EC_GROUP* group) {
    EC_POINT* p = EC_POINT_new(group);
    if (!p) {
        throw std::runtime_error(
            "musig2: EC_POINT_new() failed");
    }
    return EC_POINT_Ptr(p);
}

/// Deserialize a 33-byte SEC1 compressed point.
EC_POINT_Ptr point_from_compressed(
    const EC_GROUP* group,
    const uint8_t* data,
    size_t len,
    BN_CTX* ctx) {
    auto pt = make_point(group);
    if (!EC_POINT_oct2point(group, pt.get(), data, len, ctx)) {
        throw std::runtime_error(
            "musig2: failed to decode compressed point");
    }
    return pt;
}

/// Deserialize an x-only (32-byte) public key by assuming even parity
/// (0x02 prefix), consistent with BIP-340 conventions.
EC_POINT_Ptr point_from_xonly(
    const EC_GROUP* group,
    const uint8_t* xonly32,
    BN_CTX* ctx) {
    uint8_t compressed[33];
    compressed[0] = 0x02;
    std::memcpy(compressed + 1, xonly32, 32);
    auto pt = make_point(group);
    if (!EC_POINT_oct2point(
            group, pt.get(), compressed, 33, ctx)) {
        throw std::runtime_error(
            "musig2: failed to decode x-only pubkey");
    }
    return pt;
}

/// Serialize an EC_POINT to 33 bytes (SEC1 compressed).
std::array<uint8_t, 33> point_to_compressed(
    const EC_GROUP* group,
    const EC_POINT* pt,
    BN_CTX* ctx) {
    std::array<uint8_t, 33> out{};
    size_t len = EC_POINT_point2oct(
        group, pt, POINT_CONVERSION_COMPRESSED,
        out.data(), out.size(), ctx);
    if (len != 33) {
        throw std::runtime_error(
            "musig2: point serialization failed");
    }
    return out;
}

/// Extract the x-coordinate of an EC_POINT as 32 big-endian bytes.
std::array<uint8_t, 32> point_to_xonly(
    const EC_GROUP* group,
    const EC_POINT* pt,
    BN_CTX* ctx) {
    BN_Ptr x(BN_new());
    if (!x) {
        throw std::runtime_error("musig2: BN_new() failed");
    }
    if (!EC_POINT_get_affine_coordinates(
            group, pt, x.get(), nullptr, ctx)) {
        throw std::runtime_error(
            "musig2: failed to get affine coordinates");
    }
    std::array<uint8_t, 32> out{};
    int nbytes = BN_num_bytes(x.get());
    if (nbytes > 32) {
        throw std::runtime_error(
            "musig2: x-coordinate exceeds 32 bytes");
    }
    BN_bn2bin(x.get(), out.data() + (32 - nbytes));
    return out;
}

/// Check if the y-coordinate of a point is even.
bool point_has_even_y(
    const EC_GROUP* group,
    const EC_POINT* pt,
    BN_CTX* ctx) {
    BN_Ptr y(BN_new());
    if (!y) {
        throw std::runtime_error("musig2: BN_new() failed");
    }
    if (!EC_POINT_get_affine_coordinates(
            group, pt, nullptr, y.get(), ctx)) {
        throw std::runtime_error(
            "musig2: failed to get y coordinate");
    }
    return !BN_is_odd(y.get());
}

/// Multiply generator by scalar: result = scalar * G.
EC_POINT_Ptr scalar_base_mul(
    const EC_GROUP* group,
    const BIGNUM* scalar,
    BN_CTX* ctx) {
    auto pt = make_point(group);
    if (!EC_POINT_mul(
            group, pt.get(), scalar, nullptr, nullptr, ctx)) {
        throw std::runtime_error(
            "musig2: scalar base multiplication failed");
    }
    return pt;
}

/// Multiply point by scalar: result = scalar * P.
EC_POINT_Ptr scalar_point_mul(
    const EC_GROUP* group,
    const EC_POINT* P,
    const BIGNUM* scalar,
    BN_CTX* ctx) {
    auto pt = make_point(group);
    if (!EC_POINT_mul(
            group, pt.get(), nullptr, P, scalar, ctx)) {
        throw std::runtime_error(
            "musig2: scalar point multiplication failed");
    }
    return pt;
}

/// Add two EC points: result = A + B.
EC_POINT_Ptr point_add(
    const EC_GROUP* group,
    const EC_POINT* A,
    const EC_POINT* B,
    BN_CTX* ctx) {
    auto pt = make_point(group);
    if (!EC_POINT_add(group, pt.get(), A, B, ctx)) {
        throw std::runtime_error(
            "musig2: point addition failed");
    }
    return pt;
}

/// Negate a point in place.
void point_negate(
    const EC_GROUP* group,
    EC_POINT* pt) {
    if (!EC_POINT_invert(group, pt, nullptr)) {
        throw std::runtime_error(
            "musig2: point negation failed");
    }
}

/// Convert 32-byte big-endian buffer to BIGNUM.
BN_Ptr bn_from_32(const uint8_t* buf) {
    BN_Ptr bn(BN_bin2bn(buf, 32, nullptr));
    if (!bn) {
        throw std::runtime_error(
            "musig2: BN_bin2bn() failed");
    }
    return bn;
}

/// Convert BIGNUM to zero-padded 32-byte big-endian buffer.
std::array<uint8_t, 32> bn_to_32(const BIGNUM* bn) {
    std::array<uint8_t, 32> out{};
    int nbytes = BN_num_bytes(bn);
    if (nbytes > 32) {
        throw std::runtime_error(
            "musig2: scalar exceeds 32 bytes");
    }
    BN_bn2bin(bn, out.data() + (32 - nbytes));
    return out;
}

// ===================================================================
// MuSig2-specific hash helpers
// ===================================================================

/// Compute the nonce coefficient:
///   b = H("MuSig2/noncecoef", R_agg1 || R_agg2 || msg)
///
/// This binds the nonce coefficient to the aggregated nonce and the
/// message, ensuring each signing session uses a unique b.  The
/// aggregate pubkey is not included here (unlike BIP-327) to allow
/// the aggregation function to compute b without the session context.
/// Security is preserved because b only needs to be unique per
/// session, and (agg_nonce, msg) is already session-unique.
BN_Ptr compute_nonce_coeff(
    const MuSig2AggNonce& agg_nonce,
    const core::uint256& msg) {
    // Pre-image: R_agg1 (33) || R_agg2 (33) || msg (32) = 98 bytes.
    std::array<uint8_t, 98> preimage{};
    std::memcpy(preimage.data(),
        agg_nonce.R_agg1.data(), 33);
    std::memcpy(preimage.data() + 33,
        agg_nonce.R_agg2.data(), 33);
    std::memcpy(preimage.data() + 66,
        msg.data(), 32);

    core::uint256 hash = tagged_hash(
        "MuSig2/noncecoef",
        std::span<const uint8_t>(preimage));

    return bn_from_32(hash.data());
}

/// Compute the final nonce point R = R_agg1 + b * R_agg2, ensuring
/// even y for BIP-340 compatibility.
/// Returns (R, was_negated).
std::pair<EC_POINT_Ptr, bool> compute_final_nonce(
    const EC_GROUP* group,
    const MuSig2AggNonce& agg_nonce,
    const BIGNUM* b,
    BN_CTX* ctx) {
    auto R1 = point_from_compressed(
        group, agg_nonce.R_agg1.data(), 33, ctx);
    auto R2 = point_from_compressed(
        group, agg_nonce.R_agg2.data(), 33, ctx);

    auto R2_scaled = scalar_point_mul(group, R2.get(), b, ctx);
    auto R = point_add(group, R1.get(), R2_scaled.get(), ctx);

    bool negated = false;
    if (!point_has_even_y(group, R.get(), ctx)) {
        point_negate(group, R.get());
        negated = true;
    }

    return {std::move(R), negated};
}

/// Compute the Schnorr challenge:
///   e = H("MuSig2/challenge", R_x || agg_pubkey || msg)
BN_Ptr compute_challenge(
    const std::array<uint8_t, 32>& R_x,
    const std::array<uint8_t, 32>& agg_pubkey,
    const core::uint256& msg) {
    std::array<uint8_t, 96> preimage{};
    std::memcpy(preimage.data(), R_x.data(), 32);
    std::memcpy(preimage.data() + 32, agg_pubkey.data(), 32);
    std::memcpy(preimage.data() + 64, msg.data(), 32);

    core::uint256 hash = tagged_hash(
        "MuSig2/challenge",
        std::span<const uint8_t>(preimage));

    return bn_from_32(hash.data());
}

}  // anonymous namespace

// ===================================================================
// Key aggregation
// ===================================================================

MuSig2KeyAgg musig2_key_agg(
    const std::vector<std::array<uint8_t, 32>>& pubkeys) {
    if (pubkeys.size() < 2) {
        throw std::invalid_argument(
            "musig2_key_agg: need at least 2 public keys");
    }

    auto group = make_group();
    BN_CTX_Ptr bn_ctx(BN_CTX_new());
    if (!bn_ctx) {
        throw std::runtime_error(
            "musig2_key_agg: BN_CTX_new() failed");
    }

    // Sort pubkeys lexicographically to form the canonical ordering.
    std::vector<size_t> sorted_indices(pubkeys.size());
    std::iota(sorted_indices.begin(), sorted_indices.end(), 0);
    std::sort(sorted_indices.begin(), sorted_indices.end(),
        [&](size_t a, size_t b) {
            return pubkeys[a] < pubkeys[b];
        });

    // L = H("MuSig2/keyagg_list", P_sorted[0] || ... || P_sorted[n-1])
    std::vector<uint8_t> key_list;
    key_list.reserve(pubkeys.size() * 32);
    for (size_t idx : sorted_indices) {
        key_list.insert(key_list.end(),
            pubkeys[idx].begin(), pubkeys[idx].end());
    }
    core::uint256 L = tagged_hash(
        "MuSig2/keyagg_list",
        std::span<const uint8_t>(key_list));

    auto order = get_order(group.get(), bn_ctx.get());

    MuSig2KeyAgg result;
    result.key_coefficients.resize(pubkeys.size());

    // Q = sum(ai * Pi) where ai = H("MuSig2/keyagg_coef", L || Pi).
    auto Q = make_point(group.get());
    EC_POINT_set_to_infinity(group.get(), Q.get());

    for (size_t i = 0; i < pubkeys.size(); ++i) {
        // Coefficient pre-image: L (32) || Pi (32).
        std::array<uint8_t, 64> coeff_preimage{};
        std::memcpy(coeff_preimage.data(), L.data(), 32);
        std::memcpy(coeff_preimage.data() + 32,
            pubkeys[i].data(), 32);

        core::uint256 ai_hash = tagged_hash(
            "MuSig2/keyagg_coef",
            std::span<const uint8_t>(coeff_preimage));

        std::memcpy(result.key_coefficients[i].data(),
            ai_hash.data(), 32);

        // Reduce ai mod order.
        BN_Ptr ai = bn_from_32(ai_hash.data());
        if (!BN_mod(ai.get(), ai.get(),
                order.get(), bn_ctx.get())) {
            throw std::runtime_error(
                "musig2_key_agg: BN_mod() failed");
        }

        // Lift Pi from x-only to curve point (even y).
        auto Pi = point_from_xonly(
            group.get(), pubkeys[i].data(), bn_ctx.get());

        // Q += ai * Pi.
        auto ai_Pi = scalar_point_mul(
            group.get(), Pi.get(), ai.get(), bn_ctx.get());
        auto new_Q = point_add(
            group.get(), Q.get(), ai_Pi.get(), bn_ctx.get());
        Q = std::move(new_Q);
    }

    // Normalize Q to even y (BIP-340 x-only convention).
    if (!point_has_even_y(group.get(), Q.get(), bn_ctx.get())) {
        point_negate(group.get(), Q.get());
    }

    result.agg_pubkey = point_to_xonly(
        group.get(), Q.get(), bn_ctx.get());

    return result;
}

// ===================================================================
// Nonce generation
// ===================================================================

std::pair<MuSig2SecNonce, MuSig2PubNonce> musig2_nonce_gen(
    std::span<const uint8_t, 32> secret_key,
    std::span<const uint8_t, 32> agg_pubkey,
    const core::uint256& msg) {
    auto group = make_group();
    BN_CTX_Ptr bn_ctx(BN_CTX_new());
    if (!bn_ctx) {
        throw std::runtime_error(
            "musig2_nonce_gen: BN_CTX_new() failed");
    }

    auto order = get_order(group.get(), bn_ctx.get());

    // Deterministic nonce derivation via HMAC-Keccak256:
    //   k1 = HMAC(secret_key, "MuSig2/nonce1" || agg_pk || msg)
    //   k2 = HMAC(secret_key, "MuSig2/nonce2" || agg_pk || msg)
    auto derive_nonce = [&](std::string_view tag)
        -> BN_Ptr {
        std::vector<uint8_t> input;
        input.reserve(tag.size() + 64);
        input.insert(input.end(), tag.begin(), tag.end());
        input.insert(input.end(),
            agg_pubkey.begin(), agg_pubkey.end());
        input.insert(input.end(),
            msg.data(), msg.data() + 32);

        auto hmac_out = hmac_keccak256(
            std::span<const uint8_t>(secret_key.data(), 32),
            std::span<const uint8_t>(input));

        BN_Ptr k = bn_from_32(hmac_out.data());
        if (!BN_mod(k.get(), k.get(),
                order.get(), bn_ctx.get())) {
            throw std::runtime_error(
                "musig2_nonce_gen: BN_mod() failed");
        }
        // Ensure non-zero (astronomically unlikely to be zero).
        if (BN_is_zero(k.get())) {
            BN_one(k.get());
        }
        return k;
    };

    BN_Ptr k1_bn = derive_nonce("MuSig2/nonce1");
    BN_Ptr k2_bn = derive_nonce("MuSig2/nonce2");

    MuSig2SecNonce sec_nonce;
    sec_nonce.k1 = bn_to_32(k1_bn.get());
    sec_nonce.k2 = bn_to_32(k2_bn.get());

    // R1 = k1 * G, R2 = k2 * G.
    auto R1 = scalar_base_mul(
        group.get(), k1_bn.get(), bn_ctx.get());
    auto R2 = scalar_base_mul(
        group.get(), k2_bn.get(), bn_ctx.get());

    MuSig2PubNonce pub_nonce;
    pub_nonce.R1 = point_to_compressed(
        group.get(), R1.get(), bn_ctx.get());
    pub_nonce.R2 = point_to_compressed(
        group.get(), R2.get(), bn_ctx.get());

    return {sec_nonce, pub_nonce};
}

// ===================================================================
// Nonce aggregation
// ===================================================================

MuSig2AggNonce musig2_nonce_agg(
    const std::vector<MuSig2PubNonce>& pub_nonces) {
    if (pub_nonces.size() < 2) {
        throw std::invalid_argument(
            "musig2_nonce_agg: need at least 2 nonces");
    }

    auto group = make_group();
    BN_CTX_Ptr bn_ctx(BN_CTX_new());
    if (!bn_ctx) {
        throw std::runtime_error(
            "musig2_nonce_agg: BN_CTX_new() failed");
    }

    // Sum R1 components: R_agg1 = R1_0 + R1_1 + ... + R1_{n-1}.
    auto R1_sum = point_from_compressed(
        group.get(), pub_nonces[0].R1.data(), 33,
        bn_ctx.get());
    for (size_t i = 1; i < pub_nonces.size(); ++i) {
        auto Ri = point_from_compressed(
            group.get(), pub_nonces[i].R1.data(), 33,
            bn_ctx.get());
        R1_sum = point_add(
            group.get(), R1_sum.get(), Ri.get(),
            bn_ctx.get());
    }

    // Sum R2 components: R_agg2 = R2_0 + R2_1 + ... + R2_{n-1}.
    auto R2_sum = point_from_compressed(
        group.get(), pub_nonces[0].R2.data(), 33,
        bn_ctx.get());
    for (size_t i = 1; i < pub_nonces.size(); ++i) {
        auto Ri = point_from_compressed(
            group.get(), pub_nonces[i].R2.data(), 33,
            bn_ctx.get());
        R2_sum = point_add(
            group.get(), R2_sum.get(), Ri.get(),
            bn_ctx.get());
    }

    MuSig2AggNonce result;
    result.R_agg1 = point_to_compressed(
        group.get(), R1_sum.get(), bn_ctx.get());
    result.R_agg2 = point_to_compressed(
        group.get(), R2_sum.get(), bn_ctx.get());

    return result;
}

// ===================================================================
// Partial signing
// ===================================================================

std::array<uint8_t, 32> musig2_partial_sign(
    const MuSig2SecNonce& sec_nonce,
    std::span<const uint8_t, 32> secret_key,
    const MuSig2KeyAgg& key_agg,
    const MuSig2AggNonce& agg_nonce,
    size_t signer_index,
    const core::uint256& msg) {
    if (signer_index >= key_agg.key_coefficients.size()) {
        throw std::invalid_argument(
            "musig2_partial_sign: signer_index out of range");
    }

    auto group = make_group();
    BN_CTX_Ptr bn_ctx(BN_CTX_new());
    if (!bn_ctx) {
        throw std::runtime_error(
            "musig2_partial_sign: BN_CTX_new() failed");
    }

    auto order = get_order(group.get(), bn_ctx.get());

    // b = nonce coefficient (session-binding).
    BN_Ptr b = compute_nonce_coeff(agg_nonce, msg);
    if (!BN_mod(b.get(), b.get(),
            order.get(), bn_ctx.get())) {
        throw std::runtime_error(
            "musig2_partial_sign: BN_mod() failed");
    }

    // Compute final nonce R (with even-y normalization).
    auto [R, nonce_negated] = compute_final_nonce(
        group.get(), agg_nonce, b.get(), bn_ctx.get());
    auto R_x = point_to_xonly(
        group.get(), R.get(), bn_ctx.get());

    // e = challenge hash.
    BN_Ptr e = compute_challenge(
        R_x, key_agg.agg_pubkey, msg);
    if (!BN_mod(e.get(), e.get(),
            order.get(), bn_ctx.get())) {
        throw std::runtime_error(
            "musig2_partial_sign: BN_mod() failed");
    }

    // Load scalars.
    BN_Ptr sk = bn_from_32(secret_key.data());
    BN_Ptr k1 = bn_from_32(sec_nonce.k1.data());
    BN_Ptr k2 = bn_from_32(sec_nonce.k2.data());
    BN_Ptr ai = bn_from_32(
        key_agg.key_coefficients[signer_index].data());

    if (!BN_mod(ai.get(), ai.get(),
            order.get(), bn_ctx.get())) {
        throw std::runtime_error(
            "musig2_partial_sign: BN_mod() failed");
    }

    // k_eff = k1 + b * k2 (mod order).
    BN_Ptr bk2(BN_new());
    BN_Ptr k_eff(BN_new());
    if (!bk2 || !k_eff ||
        !BN_mod_mul(bk2.get(), b.get(), k2.get(),
            order.get(), bn_ctx.get()) ||
        !BN_mod_add(k_eff.get(), k1.get(), bk2.get(),
            order.get(), bn_ctx.get())) {
        throw std::runtime_error(
            "musig2_partial_sign: nonce computation failed");
    }

    // If final R was negated, negate k_eff: k_eff = n - k_eff.
    if (nonce_negated) {
        if (!BN_sub(k_eff.get(), order.get(), k_eff.get())) {
            throw std::runtime_error(
                "musig2_partial_sign: nonce negation failed");
        }
    }

    // s_i = k_eff + e * ai * sk (mod order).
    BN_Ptr e_ai(BN_new());
    BN_Ptr e_ai_sk(BN_new());
    BN_Ptr s_i(BN_new());

    if (!e_ai || !e_ai_sk || !s_i ||
        !BN_mod_mul(e_ai.get(), e.get(), ai.get(),
            order.get(), bn_ctx.get()) ||
        !BN_mod_mul(e_ai_sk.get(), e_ai.get(), sk.get(),
            order.get(), bn_ctx.get()) ||
        !BN_mod_add(s_i.get(), k_eff.get(), e_ai_sk.get(),
            order.get(), bn_ctx.get())) {
        throw std::runtime_error(
            "musig2_partial_sign: signature computation failed");
    }

    return bn_to_32(s_i.get());
}

// ===================================================================
// Partial verification
// ===================================================================

bool musig2_partial_verify(
    std::span<const uint8_t, 32> partial_sig,
    const MuSig2PubNonce& pub_nonce,
    std::span<const uint8_t, 32> pubkey,
    const MuSig2KeyAgg& key_agg,
    const MuSig2AggNonce& agg_nonce,
    size_t signer_index,
    const core::uint256& msg) {
    if (signer_index >= key_agg.key_coefficients.size()) {
        return false;
    }

    try {
        auto group = make_group();
        BN_CTX_Ptr bn_ctx(BN_CTX_new());
        if (!bn_ctx) return false;

        auto order = get_order(group.get(), bn_ctx.get());

        // Recompute session parameters.
        BN_Ptr b = compute_nonce_coeff(agg_nonce, msg);
        if (!BN_mod(b.get(), b.get(),
                order.get(), bn_ctx.get())) {
            return false;
        }

        auto [R, nonce_negated] = compute_final_nonce(
            group.get(), agg_nonce, b.get(), bn_ctx.get());
        auto R_x = point_to_xonly(
            group.get(), R.get(), bn_ctx.get());

        BN_Ptr e = compute_challenge(
            R_x, key_agg.agg_pubkey, msg);
        if (!BN_mod(e.get(), e.get(),
                order.get(), bn_ctx.get())) {
            return false;
        }

        BN_Ptr s_i = bn_from_32(partial_sig.data());

        // Verify: s_i * G == R_i_eff + e * ai * Pi
        // where R_i_eff is the signer's effective nonce
        // (negated if final R was negated).

        // Compute signer's effective nonce R_i_eff.
        auto R1_i = point_from_compressed(
            group.get(), pub_nonce.R1.data(), 33,
            bn_ctx.get());
        auto R2_i = point_from_compressed(
            group.get(), pub_nonce.R2.data(), 33,
            bn_ctx.get());
        auto bR2 = scalar_point_mul(
            group.get(), R2_i.get(), b.get(), bn_ctx.get());
        auto R_i_eff = point_add(
            group.get(), R1_i.get(), bR2.get(), bn_ctx.get());

        if (nonce_negated) {
            point_negate(group.get(), R_i_eff.get());
        }

        // Compute e * ai * Pi.
        BN_Ptr ai = bn_from_32(
            key_agg.key_coefficients[signer_index].data());
        if (!BN_mod(ai.get(), ai.get(),
                order.get(), bn_ctx.get())) {
            return false;
        }
        BN_Ptr e_ai(BN_new());
        if (!e_ai ||
            !BN_mod_mul(e_ai.get(), e.get(), ai.get(),
                order.get(), bn_ctx.get())) {
            return false;
        }

        auto Pi = point_from_xonly(
            group.get(), pubkey.data(), bn_ctx.get());
        auto eai_Pi = scalar_point_mul(
            group.get(), Pi.get(), e_ai.get(), bn_ctx.get());

        // LHS = s_i * G.
        auto lhs = scalar_base_mul(
            group.get(), s_i.get(), bn_ctx.get());

        // RHS = R_i_eff + e * ai * Pi.
        auto rhs = point_add(
            group.get(), R_i_eff.get(), eai_Pi.get(),
            bn_ctx.get());

        return EC_POINT_cmp(
            group.get(), lhs.get(), rhs.get(),
            bn_ctx.get()) == 0;
    } catch (...) {
        return false;
    }
}

// ===================================================================
// Final signature aggregation
// ===================================================================

std::array<uint8_t, 64> musig2_partial_sig_agg(
    const std::vector<std::array<uint8_t, 32>>& partial_sigs,
    const MuSig2AggNonce& agg_nonce,
    const core::uint256& msg) {
    if (partial_sigs.empty()) {
        throw std::invalid_argument(
            "musig2_partial_sig_agg: no partial signatures");
    }

    auto group = make_group();
    BN_CTX_Ptr bn_ctx(BN_CTX_new());
    if (!bn_ctx) {
        throw std::runtime_error(
            "musig2_partial_sig_agg: BN_CTX_new() failed");
    }
    auto order = get_order(group.get(), bn_ctx.get());

    // Recompute b and R identically to partial_sign.
    BN_Ptr b = compute_nonce_coeff(agg_nonce, msg);
    if (!BN_mod(b.get(), b.get(),
            order.get(), bn_ctx.get())) {
        throw std::runtime_error(
            "musig2_partial_sig_agg: BN_mod() failed");
    }

    auto [R, negated_unused] = compute_final_nonce(
        group.get(), agg_nonce, b.get(), bn_ctx.get());
    (void)negated_unused;
    auto R_x = point_to_xonly(
        group.get(), R.get(), bn_ctx.get());

    // s = sum(s_i) mod order.
    BN_Ptr s_sum(BN_new());
    if (!s_sum) {
        throw std::runtime_error(
            "musig2_partial_sig_agg: BN_new() failed");
    }
    BN_zero(s_sum.get());

    for (const auto& ps : partial_sigs) {
        BN_Ptr si = bn_from_32(ps.data());
        if (!BN_mod_add(s_sum.get(), s_sum.get(), si.get(),
                order.get(), bn_ctx.get())) {
            throw std::runtime_error(
                "musig2_partial_sig_agg: sum failed");
        }
    }

    // Final signature: R_x (32) || s (32).
    std::array<uint8_t, 64> signature{};
    std::memcpy(signature.data(), R_x.data(), 32);
    auto s_bytes = bn_to_32(s_sum.get());
    std::memcpy(signature.data() + 32, s_bytes.data(), 32);

    return signature;
}

}  // namespace crypto
