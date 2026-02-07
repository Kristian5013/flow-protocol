#include "crypto/schnorr.h"
#include "crypto/secp256k1.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

namespace crypto {

// ---------------------------------------------------------------------------
// RAII helpers (same pattern as secp256k1.cpp; duplicated here to keep the
// translation unit self-contained).
// ---------------------------------------------------------------------------
namespace detail {

struct BN_Deleter  { void operator()(BIGNUM* p)   const { BN_free(p); } };
struct BN_CTX_Del  { void operator()(BN_CTX* p)   const { BN_CTX_free(p); } };
struct EC_GRP_Del  { void operator()(EC_GROUP* p)  const { EC_GROUP_free(p); } };
struct EC_PT_Del   { void operator()(EC_POINT* p)  const { EC_POINT_free(p); } };

using BN_ptr     = std::unique_ptr<BIGNUM, BN_Deleter>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, BN_CTX_Del>;
using EC_GRP_ptr = std::unique_ptr<EC_GROUP, EC_GRP_Del>;
using EC_PT_ptr  = std::unique_ptr<EC_POINT, EC_PT_Del>;

}  // namespace detail

using detail::BN_ptr;
using detail::BN_CTX_ptr;
using detail::EC_GRP_ptr;
using detail::EC_PT_ptr;

// ---------------------------------------------------------------------------
// secp256k1 group singleton.
// ---------------------------------------------------------------------------
static EC_GROUP* secp256k1_group() {
    static EC_GRP_ptr group{EC_GROUP_new_by_curve_name(NID_secp256k1)};
    return group.get();
}

// ---------------------------------------------------------------------------
// Curve order as BIGNUM.
// ---------------------------------------------------------------------------
static const uint8_t SECP256K1_ORDER_BYTES[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

static const BIGNUM* secp256k1_order_bn() {
    static BN_ptr order{BN_bin2bn(SECP256K1_ORDER_BYTES,
                                   sizeof(SECP256K1_ORDER_BYTES), nullptr)};
    return order.get();
}

// ---------------------------------------------------------------------------
// Field prime p for secp256k1 (used in lift_x).
// p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
// ---------------------------------------------------------------------------
static const uint8_t SECP256K1_P_BYTES[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
};

static const BIGNUM* secp256k1_p_bn() {
    static BN_ptr p{BN_bin2bn(SECP256K1_P_BYTES,
                               sizeof(SECP256K1_P_BYTES), nullptr)};
    return p.get();
}

// ---------------------------------------------------------------------------
// Helper: serialize a BIGNUM into a zero-padded 32-byte big-endian array.
// ---------------------------------------------------------------------------
static void bn_to_bytes32(const BIGNUM* bn, uint8_t out[32]) {
    std::memset(out, 0, 32);
    int nb = BN_num_bytes(bn);
    if (nb > 0 && nb <= 32) {
        BN_bn2bin(bn, out + (32 - nb));
    }
}

// ---------------------------------------------------------------------------
// Helper: determine if an EC_POINT has an even y coordinate.
// ---------------------------------------------------------------------------
static bool has_even_y(EC_GROUP* grp, const EC_POINT* pt, BN_CTX* ctx) {
    BN_ptr x{BN_new()};
    BN_ptr y{BN_new()};
    EC_POINT_get_affine_coordinates(grp, pt, x.get(), y.get(), ctx);
    return !BN_is_odd(y.get());
}

// ---------------------------------------------------------------------------
// Helper: get the x-coordinate of a point as 32 bytes.
// ---------------------------------------------------------------------------
static void point_x_bytes(EC_GROUP* grp, const EC_POINT* pt,
                          BN_CTX* ctx, uint8_t out[32]) {
    BN_ptr x{BN_new()};
    EC_POINT_get_affine_coordinates(grp, pt, x.get(), nullptr, ctx);
    bn_to_bytes32(x.get(), out);
}

// ---------------------------------------------------------------------------
// BIP-340 tagged hash:
//   tagged_hash(tag, data) = Keccak256(Keccak256(tag) || Keccak256(tag) || data)
//
// Note: the specification uses SHA256, but the FTC protocol replaces it
// with Keccak256 throughout.
// ---------------------------------------------------------------------------
static core::uint256 tagged_hash(const char* tag,
                                 std::span<const uint8_t> data) {
    auto tag_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
    core::uint256 tag_hash = keccak256(tag_span);

    // prefix = tag_hash || tag_hash  (64 bytes)
    std::vector<uint8_t> buf;
    buf.reserve(64 + data.size());
    buf.insert(buf.end(), tag_hash.data(), tag_hash.data() + 32);
    buf.insert(buf.end(), tag_hash.data(), tag_hash.data() + 32);
    buf.insert(buf.end(), data.begin(), data.end());

    return keccak256(buf);
}

// ---------------------------------------------------------------------------
// Helper: concatenate byte spans.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> concat(
    std::initializer_list<std::span<const uint8_t>> parts) {
    size_t total = 0;
    for (auto& p : parts) total += p.size();
    std::vector<uint8_t> out;
    out.reserve(total);
    for (auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// ---------------------------------------------------------------------------
// Helper: XOR two 32-byte arrays.
// ---------------------------------------------------------------------------
static void xor_bytes32(uint8_t out[32], const uint8_t a[32],
                        const uint8_t b[32]) {
    for (int i = 0; i < 32; ++i) out[i] = a[i] ^ b[i];
}

// ---------------------------------------------------------------------------
// BIP-340 "lift_x": given a 32-byte x-coordinate, compute the point P on
// secp256k1 with even y.  Returns nullptr if x >= p or no square root exists.
// ---------------------------------------------------------------------------
static EC_PT_ptr lift_x(EC_GROUP* grp, BN_CTX* ctx,
                        const uint8_t x_bytes[32]) {
    BN_ptr x{BN_bin2bn(x_bytes, 32, nullptr)};
    if (!x || BN_cmp(x.get(), secp256k1_p_bn()) >= 0) return nullptr;

    // y^2 = x^3 + 7 mod p
    const BIGNUM* p = secp256k1_p_bn();
    BN_ptr x3{BN_new()};
    BN_ptr y_sq{BN_new()};
    BN_ptr seven{BN_new()};
    BN_set_word(seven.get(), 7);

    BN_mod_sqr(x3.get(), x.get(), p, ctx);
    BN_mod_mul(x3.get(), x3.get(), x.get(), p, ctx);
    BN_mod_add(y_sq.get(), x3.get(), seven.get(), p, ctx);

    BN_ptr y{BN_mod_sqrt(nullptr, y_sq.get(), p, ctx)};
    if (!y) return nullptr;

    // Choose even y.
    if (BN_is_odd(y.get())) {
        BN_sub(y.get(), p, y.get());
    }

    EC_PT_ptr pt{EC_POINT_new(grp)};
    if (!EC_POINT_set_affine_coordinates(grp, pt.get(), x.get(), y.get(),
                                         ctx)) {
        return nullptr;
    }
    return pt;
}

// ---------------------------------------------------------------------------
// SchnorrKey construction
// ---------------------------------------------------------------------------

core::Result<SchnorrKey> SchnorrKey::from_secret(
    std::span<const uint8_t, 32> secret) {
    BN_ptr s_bn{BN_bin2bn(secret.data(), 32, nullptr)};
    if (!s_bn || BN_is_zero(s_bn.get()) ||
        BN_cmp(s_bn.get(), secp256k1_order_bn()) >= 0) {
        return core::Result<SchnorrKey>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "secret key out of range for secp256k1"}};
    }

    SchnorrKey key;
    std::memcpy(key.secret_.data(), secret.data(), 32);
    key.has_key_ = true;
    return core::Result<SchnorrKey>{std::move(key)};
}

SchnorrKey SchnorrKey::from_eckey(const ECKey& eckey) {
    SchnorrKey key;
    if (!eckey.is_valid()) return key;
    auto sec = eckey.secret();
    std::memcpy(key.secret_.data(), sec.data(), 32);
    key.has_key_ = true;
    return key;
}

bool SchnorrKey::is_valid() const { return has_key_; }

// ---------------------------------------------------------------------------
// x-only public key
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> SchnorrKey::pubkey() const {
    std::array<uint8_t, 32> out{};
    if (!has_key_) return out;

    EC_GROUP* grp = secp256k1_group();
    BN_CTX_ptr ctx{BN_CTX_new()};

    BN_ptr d{BN_bin2bn(secret_.data(), 32, nullptr)};
    EC_PT_ptr P{EC_POINT_new(grp)};
    EC_POINT_mul(grp, P.get(), d.get(), nullptr, nullptr, ctx.get());

    point_x_bytes(grp, P.get(), ctx.get(), out.data());
    return out;
}

// ---------------------------------------------------------------------------
// BIP-340 Signing
// ---------------------------------------------------------------------------

std::array<uint8_t, 64> SchnorrKey::sign(const core::uint256& hash) const {
    std::array<uint8_t, 32> aux{};
    RAND_bytes(aux.data(), 32);
    return sign(hash, aux);
}

std::array<uint8_t, 64> SchnorrKey::sign(
    const core::uint256& hash,
    std::span<const uint8_t, 32> aux_rand) const {
    std::array<uint8_t, 64> result{};
    if (!has_key_) return result;

    EC_GROUP* grp = secp256k1_group();
    BN_CTX_ptr ctx{BN_CTX_new()};
    const BIGNUM* n = secp256k1_order_bn();

    // Step 1: d' = secret_, P = d' * G
    BN_ptr d_prime{BN_bin2bn(secret_.data(), 32, nullptr)};
    EC_PT_ptr P{EC_POINT_new(grp)};
    EC_POINT_mul(grp, P.get(), d_prime.get(), nullptr, nullptr, ctx.get());

    // Step 2: d = d' if has_even_y(P), else n - d'
    BN_ptr d{BN_dup(d_prime.get())};
    if (!has_even_y(grp, P.get(), ctx.get())) {
        BN_sub(d.get(), n, d.get());
    }

    // bytes(d) -- 32-byte big-endian
    uint8_t d_bytes[32];
    bn_to_bytes32(d.get(), d_bytes);

    // bytes(P) -- x-coordinate, 32 bytes
    uint8_t p_bytes[32];
    point_x_bytes(grp, P.get(), ctx.get(), p_bytes);

    // Step 3: t = xor(bytes(d), tagged_hash("BIP0340/aux", aux_rand))
    core::uint256 aux_hash = tagged_hash("BIP0340/aux",
        std::span<const uint8_t, 32>{aux_rand.data(), 32});
    uint8_t t[32];
    xor_bytes32(t, d_bytes, aux_hash.data());

    // Step 4: rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m)
    auto nonce_input = concat({
        std::span<const uint8_t>(t, 32),
        std::span<const uint8_t>(p_bytes, 32),
        std::span<const uint8_t>(hash.data(), 32)
    });
    core::uint256 rand_hash = tagged_hash("BIP0340/nonce", nonce_input);

    // Step 5: k' = int(rand) mod n,  fail if k' == 0
    BN_ptr k_prime{BN_bin2bn(rand_hash.data(), 32, nullptr)};
    BN_mod(k_prime.get(), k_prime.get(), n, ctx.get());
    if (BN_is_zero(k_prime.get())) {
        // Extremely unlikely; return zero signature to indicate failure.
        OPENSSL_cleanse(d_bytes, sizeof(d_bytes));
        return result;
    }

    // Step 6: R = k' * G, k = k' if has_even_y(R), else n - k'
    EC_PT_ptr R{EC_POINT_new(grp)};
    EC_POINT_mul(grp, R.get(), k_prime.get(), nullptr, nullptr, ctx.get());

    BN_ptr k{BN_dup(k_prime.get())};
    if (!has_even_y(grp, R.get(), ctx.get())) {
        BN_sub(k.get(), n, k.get());
    }

    // bytes(R) -- x-coordinate
    uint8_t r_bytes[32];
    point_x_bytes(grp, R.get(), ctx.get(), r_bytes);

    // Step 7: e = int(tagged_hash("BIP0340/challenge",
    //                              bytes(R) || bytes(P) || m)) mod n
    auto challenge_input = concat({
        std::span<const uint8_t>(r_bytes, 32),
        std::span<const uint8_t>(p_bytes, 32),
        std::span<const uint8_t>(hash.data(), 32)
    });
    core::uint256 e_hash = tagged_hash("BIP0340/challenge", challenge_input);

    BN_ptr e{BN_bin2bn(e_hash.data(), 32, nullptr)};
    BN_mod(e.get(), e.get(), n, ctx.get());

    // Step 8: sig = bytes(R) || bytes((k + e * d) mod n)
    BN_ptr ed{BN_new()};
    BN_mod_mul(ed.get(), e.get(), d.get(), n, ctx.get());
    BN_ptr s{BN_new()};
    BN_mod_add(s.get(), k.get(), ed.get(), n, ctx.get());

    uint8_t s_bytes[32];
    bn_to_bytes32(s.get(), s_bytes);

    std::memcpy(result.data(), r_bytes, 32);
    std::memcpy(result.data() + 32, s_bytes, 32);

    OPENSSL_cleanse(d_bytes, sizeof(d_bytes));
    OPENSSL_cleanse(t, sizeof(t));
    return result;
}

// ---------------------------------------------------------------------------
// BIP-340 Verification
// ---------------------------------------------------------------------------

bool SchnorrKey::verify(std::span<const uint8_t, 32> pubkey,
                        const core::uint256& hash,
                        std::span<const uint8_t, 64> sig) {
    EC_GROUP* grp = secp256k1_group();
    BN_CTX_ptr ctx{BN_CTX_new()};
    const BIGNUM* n = secp256k1_order_bn();
    const BIGNUM* p = secp256k1_p_bn();

    // Extract r and s from the signature.
    BN_ptr r{BN_bin2bn(sig.data(), 32, nullptr)};
    BN_ptr s{BN_bin2bn(sig.data() + 32, 32, nullptr)};
    if (!r || !s) return false;

    // Fail if r >= p or s >= n.
    if (BN_cmp(r.get(), p) >= 0) return false;
    if (BN_cmp(s.get(), n) >= 0) return false;

    // lift_x(pubkey) -> P
    EC_PT_ptr P = lift_x(grp, ctx.get(), pubkey.data());
    if (!P) return false;

    // e = int(tagged_hash("BIP0340/challenge", r_bytes || P || m)) mod n
    auto challenge_input = concat({
        std::span<const uint8_t>(sig.data(), 32),
        std::span<const uint8_t>(pubkey.data(), 32),
        std::span<const uint8_t>(hash.data(), 32)
    });
    core::uint256 e_hash = tagged_hash("BIP0340/challenge", challenge_input);

    BN_ptr e{BN_bin2bn(e_hash.data(), 32, nullptr)};
    BN_mod(e.get(), e.get(), n, ctx.get());

    // R = s * G - e * P
    // Compute n - e for the subtraction:  R = s*G + (n-e)*P
    BN_ptr neg_e{BN_new()};
    BN_sub(neg_e.get(), n, e.get());

    // R = s*G + neg_e*P  (EC_POINT_mul computes: R = s*G + neg_e*P)
    EC_PT_ptr sG{EC_POINT_new(grp)};
    EC_POINT_mul(grp, sG.get(), s.get(), nullptr, nullptr, ctx.get());

    EC_PT_ptr neg_eP{EC_POINT_new(grp)};
    EC_POINT_mul(grp, neg_eP.get(), nullptr, P.get(), neg_e.get(), ctx.get());

    EC_PT_ptr R{EC_POINT_new(grp)};
    EC_POINT_add(grp, R.get(), sG.get(), neg_eP.get(), ctx.get());

    // Fail if R is at infinity.
    if (EC_POINT_is_at_infinity(grp, R.get())) return false;

    // Fail if R has odd y.
    if (!has_even_y(grp, R.get(), ctx.get())) return false;

    // Fail if x(R) != r.
    BN_ptr rx{BN_new()};
    EC_POINT_get_affine_coordinates(grp, R.get(), rx.get(), nullptr,
                                    ctx.get());
    return BN_cmp(rx.get(), r.get()) == 0;
}

}  // namespace crypto
