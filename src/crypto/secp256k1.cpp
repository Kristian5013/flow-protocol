#include "crypto/secp256k1.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

namespace crypto {

// ---------------------------------------------------------------------------
// secp256k1 curve order (big-endian).
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// ---------------------------------------------------------------------------
static const uint8_t SECP256K1_ORDER[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

// half-order = n / 2  (for low-S normalisation)
static const uint8_t SECP256K1_HALF_ORDER[] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
    0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0
};

// ---------------------------------------------------------------------------
// RAII helpers for OpenSSL objects
// ---------------------------------------------------------------------------
struct BN_Deleter  { void operator()(BIGNUM* p)       const { BN_free(p); } };
struct BN_CTX_Del  { void operator()(BN_CTX* p)       const { BN_CTX_free(p); } };
struct EC_GRP_Del  { void operator()(EC_GROUP* p)     const { EC_GROUP_free(p); } };
struct EC_PT_Del   { void operator()(EC_POINT* p)     const { EC_POINT_free(p); } };
struct EVP_KEY_Del { void operator()(EVP_PKEY* p)     const { EVP_PKEY_free(p); } };
struct EVP_CTX_Del { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EVP_MD_Del  { void operator()(EVP_MD_CTX* p)   const { EVP_MD_CTX_free(p); } };
struct PB_Deleter  { void operator()(OSSL_PARAM_BLD* p) const {
    OSSL_PARAM_BLD_free(p);
} };
struct OP_Deleter  { void operator()(OSSL_PARAM* p)   const {
    OSSL_PARAM_free(p);
} };

using BN_ptr      = std::unique_ptr<BIGNUM, BN_Deleter>;
using BN_CTX_ptr  = std::unique_ptr<BN_CTX, BN_CTX_Del>;
using EC_GRP_ptr  = std::unique_ptr<EC_GROUP, EC_GRP_Del>;
using EC_PT_ptr   = std::unique_ptr<EC_POINT, EC_PT_Del>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, EVP_KEY_Del>;
using EVP_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, EVP_CTX_Del>;
using EVP_MD_ptr  = std::unique_ptr<EVP_MD_CTX, EVP_MD_Del>;
using PB_ptr      = std::unique_ptr<OSSL_PARAM_BLD, PB_Deleter>;
using OP_ptr      = std::unique_ptr<OSSL_PARAM, OP_Deleter>;

// ---------------------------------------------------------------------------
// Internal: obtain a reusable EC_GROUP for secp256k1.
// ---------------------------------------------------------------------------
static EC_GROUP* secp256k1_group() {
    static EC_GRP_ptr group{
        EC_GROUP_new_by_curve_name(NID_secp256k1)};
    return group.get();
}

// ---------------------------------------------------------------------------
// Internal: curve order as BIGNUM.
// ---------------------------------------------------------------------------
static const BIGNUM* secp256k1_order_bn() {
    static BN_ptr order{BN_bin2bn(SECP256K1_ORDER,
                                   sizeof(SECP256K1_ORDER),
                                   nullptr)};
    return order.get();
}

static const BIGNUM* secp256k1_half_order_bn() {
    static BN_ptr half{BN_bin2bn(SECP256K1_HALF_ORDER,
                                  sizeof(SECP256K1_HALF_ORDER),
                                  nullptr)};
    return half.get();
}

// ---------------------------------------------------------------------------
// Internal: build an EVP_PKEY from a 32-byte secret using OSSL_PARAM.
// ---------------------------------------------------------------------------
static EVP_PKEY* build_pkey_from_secret(const uint8_t* secret_32) {
    PB_ptr bld{OSSL_PARAM_BLD_new()};
    if (!bld) return nullptr;

    // Push the group name.
    if (!OSSL_PARAM_BLD_push_utf8_string(
            bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0)) {
        return nullptr;
    }

    // Push the private key as unsigned big-endian integer.
    // NOTE: OSSL_PARAM_BLD_push_BN stores a pointer to the BIGNUM and
    // defers serialization to OSSL_PARAM_BLD_to_param(). The BIGNUM must
    // remain alive until to_param() is called (OpenSSL 3.0 behavior).
    BN_ptr priv_bn{BN_bin2bn(secret_32, 32, nullptr)};
    if (!priv_bn) return nullptr;
    if (!OSSL_PARAM_BLD_push_BN(
            bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv_bn.get())) {
        return nullptr;
    }

    // Compute the public key = secret * G as an uncompressed point.
    BN_CTX_ptr ctx{BN_CTX_new()};
    EC_GROUP* grp = secp256k1_group();
    EC_PT_ptr pub_pt{EC_POINT_new(grp)};
    if (!EC_POINT_mul(grp, pub_pt.get(), priv_bn.get(), nullptr, nullptr,
                      ctx.get())) {
        return nullptr;
    }

    // Serialize uncompressed: 0x04 || x || y  (65 bytes).
    uint8_t pub_buf[65];
    size_t pub_len = EC_POINT_point2oct(
        grp, pub_pt.get(), POINT_CONVERSION_UNCOMPRESSED,
        pub_buf, sizeof(pub_buf), ctx.get());
    if (pub_len != 65) return nullptr;

    if (!OSSL_PARAM_BLD_push_octet_string(
            bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len)) {
        return nullptr;
    }

    // Build params - priv_bn must still be alive here (OpenSSL 3.0).
    OP_ptr params{OSSL_PARAM_BLD_to_param(bld.get())};
    if (!params) return nullptr;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) return nullptr;
    EVP_CTX_ptr pctx_guard{pctx};

    if (EVP_PKEY_fromdata_init(pctx) <= 0) return nullptr;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
                          params.get()) <= 0) {
        return nullptr;
    }
    return pkey;
}

// ---------------------------------------------------------------------------
// Internal: build an EVP_PKEY holding only a public key from raw SEC1 bytes.
// ---------------------------------------------------------------------------
static EVP_PKEY* build_pkey_from_pubkey(const uint8_t* pub_data,
                                        size_t pub_len) {
    PB_ptr bld{OSSL_PARAM_BLD_new()};
    if (!bld) return nullptr;

    if (!OSSL_PARAM_BLD_push_utf8_string(
            bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0)) {
        return nullptr;
    }
    if (!OSSL_PARAM_BLD_push_octet_string(
            bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub_data, pub_len)) {
        return nullptr;
    }

    OP_ptr params{OSSL_PARAM_BLD_to_param(bld.get())};
    if (!params) return nullptr;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) return nullptr;
    EVP_CTX_ptr pctx_guard{pctx};

    if (EVP_PKEY_fromdata_init(pctx) <= 0) return nullptr;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY,
                          params.get()) <= 0) {
        return nullptr;
    }
    return pkey;
}

// ---------------------------------------------------------------------------
// Internal: extract the uncompressed public key (65 bytes) from EVP_PKEY.
// ---------------------------------------------------------------------------
static bool extract_pubkey_uncompressed(EVP_PKEY* pkey, uint8_t out[65]) {
    size_t len = 0;
    if (!EVP_PKEY_get_octet_string_param(
            pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &len)) {
        return false;
    }
    if (len != 65) return false;
    if (!EVP_PKEY_get_octet_string_param(
            pkey, OSSL_PKEY_PARAM_PUB_KEY, out, 65, &len)) {
        return false;
    }
    return len == 65;
}

// ---------------------------------------------------------------------------
// Internal: compress an uncompressed 65-byte pubkey into 33 bytes.
// ---------------------------------------------------------------------------
static void compress_pubkey(const uint8_t uncompressed[65],
                            uint8_t compressed[33]) {
    // 0x02 if y is even, 0x03 if odd.
    compressed[0] = (uncompressed[64] & 1) ? 0x03 : 0x02;
    std::memcpy(compressed + 1, uncompressed + 1, 32);
}

// ---------------------------------------------------------------------------
// Internal: DER-encode two 32-byte big-endian integers (r, s) into an ECDSA
// DER SEQUENCE { INTEGER r, INTEGER s }.
// ---------------------------------------------------------------------------
static void encode_der_integer(const uint8_t* val, size_t val_len,
                               std::vector<uint8_t>& out) {
    // Skip leading zeros but keep at least one byte.
    size_t skip = 0;
    while (skip < val_len - 1 && val[skip] == 0) ++skip;
    const uint8_t* start = val + skip;
    size_t len = val_len - skip;

    bool need_pad = (start[0] & 0x80) != 0;
    out.push_back(0x02);  // INTEGER tag
    out.push_back(static_cast<uint8_t>(len + (need_pad ? 1 : 0)));
    if (need_pad) out.push_back(0x00);
    out.insert(out.end(), start, start + len);
}

static std::vector<uint8_t> compact_to_der(const uint8_t* r32,
                                           const uint8_t* s32) {
    std::vector<uint8_t> inner;
    inner.reserve(72);
    encode_der_integer(r32, 32, inner);
    encode_der_integer(s32, 32, inner);

    std::vector<uint8_t> der;
    der.reserve(inner.size() + 2);
    der.push_back(0x30);  // SEQUENCE
    der.push_back(static_cast<uint8_t>(inner.size()));
    der.insert(der.end(), inner.begin(), inner.end());
    return der;
}

// ---------------------------------------------------------------------------
// Internal: parse DER signature into r (32 bytes) and s (32 bytes).
// Returns false on malformed input.
// ---------------------------------------------------------------------------
static bool der_to_compact(const uint8_t* der, size_t der_len,
                           uint8_t r_out[32], uint8_t s_out[32]) {
    if (der_len < 8 || der[0] != 0x30) return false;
    size_t seq_len = der[1];
    if (seq_len + 2 > der_len) return false;

    const uint8_t* p = der + 2;
    const uint8_t* end = der + 2 + seq_len;

    auto read_int = [&](uint8_t out[32]) -> bool {
        if (p >= end || *p != 0x02) return false;
        ++p;
        if (p >= end) return false;
        size_t ilen = *p++;
        if (p + ilen > end) return false;

        // Strip leading zero padding.
        const uint8_t* istart = p;
        size_t ilen_raw = ilen;
        if (ilen > 1 && istart[0] == 0x00) {
            ++istart;
            --ilen_raw;
        }
        if (ilen_raw > 32) return false;

        std::memset(out, 0, 32);
        std::memcpy(out + 32 - ilen_raw, istart, ilen_raw);
        p += ilen;
        return true;
    };

    if (!read_int(r_out)) return false;
    if (!read_int(s_out)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Internal: DER-sign a 32-byte hash using EVP_PKEY (raw digest mode).
// ---------------------------------------------------------------------------
static std::vector<uint8_t> evp_sign_hash(EVP_PKEY* pkey,
                                          const uint8_t* hash32) {
    EVP_MD_ptr md_ctx{EVP_MD_CTX_new()};
    if (!md_ctx) return {};

    // We already have the hash, so use a NULL digest (raw sign).
    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr,
                           pkey) <= 0) {
        return {};
    }

    // Determine required length.
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len,
                       hash32, 32) <= 0) {
        return {};
    }

    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(md_ctx.get(), sig.data(), &sig_len,
                       hash32, 32) <= 0) {
        return {};
    }
    sig.resize(sig_len);
    return sig;
}

// ---------------------------------------------------------------------------
// Internal: DER-verify a hash using EVP_PKEY (raw digest mode).
// ---------------------------------------------------------------------------
static bool evp_verify_hash(EVP_PKEY* pkey, const uint8_t* hash32,
                            const uint8_t* der_sig, size_t der_sig_len) {
    EVP_MD_ptr md_ctx{EVP_MD_CTX_new()};
    if (!md_ctx) return false;

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr,
                             pkey) <= 0) {
        return false;
    }
    return EVP_DigestVerify(md_ctx.get(), der_sig, der_sig_len,
                            hash32, 32) == 1;
}

// ---------------------------------------------------------------------------
// ECKey lifetime
// ---------------------------------------------------------------------------

ECKey::~ECKey() {
    if (pkey_) EVP_PKEY_free(pkey_);
    OPENSSL_cleanse(secret_.data(), secret_.size());
}

ECKey::ECKey(ECKey&& other) noexcept
    : secret_(other.secret_),
      has_key_(other.has_key_),
      pkey_(other.pkey_) {
    other.pkey_ = nullptr;
    other.has_key_ = false;
    OPENSSL_cleanse(other.secret_.data(), other.secret_.size());
}

ECKey& ECKey::operator=(ECKey&& other) noexcept {
    if (this != &other) {
        if (pkey_) EVP_PKEY_free(pkey_);
        OPENSSL_cleanse(secret_.data(), secret_.size());

        secret_ = other.secret_;
        has_key_ = other.has_key_;
        pkey_ = other.pkey_;

        other.pkey_ = nullptr;
        other.has_key_ = false;
        OPENSSL_cleanse(other.secret_.data(), other.secret_.size());
    }
    return *this;
}

// ---------------------------------------------------------------------------
// Key construction
// ---------------------------------------------------------------------------

ECKey ECKey::generate() {
    // Use EVP_PKEY_Q_keygen for one-shot key generation.
    EVP_PKEY* raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "secp256k1");
    if (!raw) return {};

    ECKey key;
    key.pkey_ = raw;

    // Extract the private key scalar.
    BIGNUM* priv_bn = nullptr;
    if (!EVP_PKEY_get_bn_param(raw, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn)) {
        EVP_PKEY_free(raw);
        return {};
    }

    std::memset(key.secret_.data(), 0, 32);
    int bn_bytes = BN_num_bytes(priv_bn);
    if (bn_bytes > 0 && bn_bytes <= 32) {
        BN_bn2bin(priv_bn, key.secret_.data() + (32 - bn_bytes));
    }
    BN_free(priv_bn);
    key.has_key_ = true;
    return key;
}

core::Result<ECKey> ECKey::from_secret(std::span<const uint8_t, 32> secret) {
    // Validate: secret must be in [1, n-1].
    BN_ptr s_bn{BN_bin2bn(secret.data(), 32, nullptr)};
    if (!s_bn || BN_is_zero(s_bn.get()) ||
        BN_cmp(s_bn.get(), secp256k1_order_bn()) >= 0) {
        return core::Result<ECKey>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "secret key out of range for secp256k1"}};
    }

    ECKey key;
    std::memcpy(key.secret_.data(), secret.data(), 32);
    key.has_key_ = true;
    key.rebuild_pkey();

    if (!key.pkey_) {
        return core::Result<ECKey>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "failed to build EVP_PKEY from secret"}};
    }
    return core::Result<ECKey>{std::move(key)};
}

bool ECKey::is_valid() const { return has_key_; }

std::array<uint8_t, 32> ECKey::secret() const { return secret_; }

void ECKey::rebuild_pkey() {
    if (pkey_) {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }
    if (!has_key_) return;
    pkey_ = build_pkey_from_secret(secret_.data());
}

// ---------------------------------------------------------------------------
// Public key accessors
// ---------------------------------------------------------------------------

std::array<uint8_t, 33> ECKey::pubkey_compressed() const {
    std::array<uint8_t, 33> out{};
    if (!pkey_) return out;
    uint8_t uncomp[65];
    if (extract_pubkey_uncompressed(pkey_, uncomp)) {
        compress_pubkey(uncomp, out.data());
    }
    return out;
}

std::array<uint8_t, 65> ECKey::pubkey_uncompressed() const {
    std::array<uint8_t, 65> out{};
    if (!pkey_) return out;
    extract_pubkey_uncompressed(pkey_, out.data());
    return out;
}

// ---------------------------------------------------------------------------
// ECDSA signing
// ---------------------------------------------------------------------------

std::vector<uint8_t> ECKey::sign(const core::uint256& hash) const {
    if (!pkey_) return {};
    std::vector<uint8_t> der = evp_sign_hash(pkey_, hash.data());
    if (der.empty()) return {};
    ecdsa_normalize_s(der);
    return der;
}

std::pair<std::array<uint8_t, 64>, int> ECKey::sign_compact(
    const core::uint256& hash) const {
    std::array<uint8_t, 64> compact{};
    int rec_id = -1;

    std::vector<uint8_t> der = sign(hash);
    if (der.empty()) return {compact, rec_id};

    uint8_t r[32], s[32];
    if (!der_to_compact(der.data(), der.size(), r, s)) return {compact, rec_id};

    std::memcpy(compact.data(), r, 32);
    std::memcpy(compact.data() + 32, s, 32);

    // Determine recovery id by trying each and comparing pubkeys.
    auto my_pub = pubkey_compressed();
    for (int id = 0; id < 4; ++id) {
        auto result = recover_compact(hash, compact, id);
        if (result.ok() && result.value() == my_pub) {
            rec_id = id;
            break;
        }
    }
    return {compact, rec_id};
}

// ---------------------------------------------------------------------------
// ECDSA verification
// ---------------------------------------------------------------------------

bool ECKey::verify(std::span<const uint8_t> pubkey,
                   const core::uint256& hash,
                   std::span<const uint8_t> der_sig) {
    if (pubkey.size() != 33 && pubkey.size() != 65) return false;
    EVP_PKEY* pk = build_pkey_from_pubkey(pubkey.data(), pubkey.size());
    if (!pk) return false;
    EVP_KEY_ptr guard{pk};
    return evp_verify_hash(pk, hash.data(), der_sig.data(), der_sig.size());
}

bool ECKey::verify_compact(std::span<const uint8_t> pubkey,
                           const core::uint256& hash,
                           std::span<const uint8_t, 64> sig) {
    std::vector<uint8_t> der = compact_to_der(sig.data(), sig.data() + 32);
    return verify(pubkey, hash, der);
}

// ---------------------------------------------------------------------------
// Public key recovery
// ---------------------------------------------------------------------------

core::Result<std::array<uint8_t, 33>> ECKey::recover_compact(
    const core::uint256& hash,
    std::span<const uint8_t, 64> sig,
    int recovery_id) {
    if (recovery_id < 0 || recovery_id > 3) {
        return core::Result<std::array<uint8_t, 33>>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "recovery_id must be 0..3"}};
    }

    EC_GROUP* grp = secp256k1_group();
    BN_CTX_ptr ctx{BN_CTX_new()};
    const BIGNUM* order = secp256k1_order_bn();

    // r and s from the compact signature.
    BN_ptr r_bn{BN_bin2bn(sig.data(), 32, nullptr)};
    BN_ptr s_bn{BN_bin2bn(sig.data() + 32, 32, nullptr)};
    if (!r_bn || !s_bn || BN_is_zero(r_bn.get()) ||
        BN_is_zero(s_bn.get())) {
        return core::Result<std::array<uint8_t, 33>>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "invalid compact signature (r or s is zero)"}};
    }

    // x = r + (recovery_id >> 1) * n
    BN_ptr x_bn{BN_dup(r_bn.get())};
    if (recovery_id & 2) {
        BN_add(x_bn.get(), x_bn.get(), order);
    }

    // Recover y from x.  Try to construct point R = (x, y).
    // We derive y from the curve equation y^2 = x^3 + 7.
    BN_ptr p_field{BN_new()};
    EC_GROUP_get_curve(grp, p_field.get(), nullptr, nullptr, ctx.get());
    BN_ptr y_sq{BN_new()};
    BN_ptr x3{BN_new()};
    BN_ptr seven{BN_new()};
    BN_set_word(seven.get(), 7);

    // x^3 mod p
    BN_mod_sqr(x3.get(), x_bn.get(), p_field.get(), ctx.get());
    BN_mod_mul(x3.get(), x3.get(), x_bn.get(), p_field.get(), ctx.get());
    // x^3 + 7 mod p
    BN_mod_add(y_sq.get(), x3.get(), seven.get(), p_field.get(), ctx.get());

    // y = sqrt(y_sq) mod p  -- Tonelli-Shanks via BN_mod_sqrt
    BN_ptr y_bn{BN_mod_sqrt(nullptr, y_sq.get(), p_field.get(), ctx.get())};
    if (!y_bn) {
        return core::Result<std::array<uint8_t, 33>>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "no valid curve point for given r and recovery_id"}};
    }

    // Choose even/odd y based on recovery_id bit 0.
    bool y_is_odd = BN_is_odd(y_bn.get());
    bool want_odd = (recovery_id & 1) != 0;
    if (y_is_odd != want_odd) {
        BN_sub(y_bn.get(), p_field.get(), y_bn.get());
    }

    // Construct point R.
    EC_PT_ptr R{EC_POINT_new(grp)};
    if (!EC_POINT_set_affine_coordinates(
            grp, R.get(), x_bn.get(), y_bn.get(), ctx.get())) {
        return core::Result<std::array<uint8_t, 33>>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "failed to set affine coordinates for R"}};
    }

    // Compute public key: Q = r^{-1} * (s*R - e*G)
    BN_ptr e_bn{BN_bin2bn(hash.data(), 32, nullptr)};
    BN_ptr r_inv{BN_mod_inverse(nullptr, r_bn.get(), order, ctx.get())};
    if (!r_inv) {
        return core::Result<std::array<uint8_t, 33>>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "r has no modular inverse"}};
    }

    // s*R
    EC_PT_ptr sR{EC_POINT_new(grp)};
    EC_POINT_mul(grp, sR.get(), nullptr, R.get(), s_bn.get(), ctx.get());

    // e*G  (use generator)
    EC_PT_ptr eG{EC_POINT_new(grp)};
    EC_POINT_mul(grp, eG.get(), e_bn.get(), nullptr, nullptr, ctx.get());

    // neg_eG = -e*G
    EC_PT_ptr neg_eG{EC_POINT_dup(eG.get(), grp)};
    EC_POINT_invert(grp, neg_eG.get(), ctx.get());

    // sR - eG
    EC_PT_ptr sum{EC_POINT_new(grp)};
    EC_POINT_add(grp, sum.get(), sR.get(), neg_eG.get(), ctx.get());

    // Q = r_inv * sum
    EC_PT_ptr Q{EC_POINT_new(grp)};
    EC_POINT_mul(grp, Q.get(), nullptr, sum.get(), r_inv.get(), ctx.get());

    if (EC_POINT_is_at_infinity(grp, Q.get())) {
        return core::Result<std::array<uint8_t, 33>>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "recovered point is at infinity"}};
    }

    // Serialize compressed.
    std::array<uint8_t, 33> result{};
    size_t len = EC_POINT_point2oct(
        grp, Q.get(), POINT_CONVERSION_COMPRESSED,
        result.data(), result.size(), ctx.get());
    if (len != 33) {
        return core::Result<std::array<uint8_t, 33>>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "failed to serialize recovered pubkey"}};
    }
    return core::Result<std::array<uint8_t, 33>>{result};
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

core::Result<core::uint256> ECKey::ecdh(
    std::span<const uint8_t> other_pubkey) const {
    if (!pkey_) {
        return core::Result<core::uint256>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "ECKey has no private key for ECDH"}};
    }

    EVP_PKEY* peer = build_pkey_from_pubkey(other_pubkey.data(),
                                            other_pubkey.size());
    if (!peer) {
        return core::Result<core::uint256>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "invalid peer public key for ECDH"}};
    }
    EVP_KEY_ptr peer_guard{peer};

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(pkey_, nullptr);
    if (!dctx) {
        return core::Result<core::uint256>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "EVP_PKEY_CTX_new failed for ECDH"}};
    }
    EVP_CTX_ptr dctx_guard{dctx};

    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, peer) <= 0) {
        return core::Result<core::uint256>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "ECDH derive init/set_peer failed"}};
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(dctx, nullptr, &secret_len) <= 0) {
        return core::Result<core::uint256>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "ECDH derive length query failed"}};
    }

    std::vector<uint8_t> raw_secret(secret_len);
    if (EVP_PKEY_derive(dctx, raw_secret.data(), &secret_len) <= 0) {
        return core::Result<core::uint256>{core::Error{
            core::ErrorCode::CRYPTO_ERROR,
            "ECDH derive failed"}};
    }
    raw_secret.resize(secret_len);

    // Hash the raw shared secret with keccak256 to produce the final key.
    core::uint256 result = keccak256(raw_secret);
    OPENSSL_cleanse(raw_secret.data(), raw_secret.size());
    return core::Result<core::uint256>{result};
}

// ---------------------------------------------------------------------------
// Tweak operations (Taproot / BIP32 compatible)
// ---------------------------------------------------------------------------

ECKey& ECKey::tweak_add(std::span<const uint8_t, 32> tweak) {
    if (!has_key_) return *this;

    BN_CTX_ptr ctx{BN_CTX_new()};
    const BIGNUM* order = secp256k1_order_bn();

    BN_ptr sec{BN_bin2bn(secret_.data(), 32, nullptr)};
    BN_ptr tw{BN_bin2bn(tweak.data(), 32, nullptr)};

    BN_mod_add(sec.get(), sec.get(), tw.get(), order, ctx.get());

    // If the result is zero, the key is invalid.
    if (BN_is_zero(sec.get())) {
        has_key_ = false;
        if (pkey_) { EVP_PKEY_free(pkey_); pkey_ = nullptr; }
        OPENSSL_cleanse(secret_.data(), secret_.size());
        return *this;
    }

    std::memset(secret_.data(), 0, 32);
    int bn_bytes = BN_num_bytes(sec.get());
    if (bn_bytes > 0 && bn_bytes <= 32) {
        BN_bn2bin(sec.get(), secret_.data() + (32 - bn_bytes));
    }
    rebuild_pkey();
    return *this;
}

ECKey& ECKey::tweak_mul(std::span<const uint8_t, 32> tweak) {
    if (!has_key_) return *this;

    BN_CTX_ptr ctx{BN_CTX_new()};
    const BIGNUM* order = secp256k1_order_bn();

    BN_ptr sec{BN_bin2bn(secret_.data(), 32, nullptr)};
    BN_ptr tw{BN_bin2bn(tweak.data(), 32, nullptr)};

    BN_mod_mul(sec.get(), sec.get(), tw.get(), order, ctx.get());

    if (BN_is_zero(sec.get())) {
        has_key_ = false;
        if (pkey_) { EVP_PKEY_free(pkey_); pkey_ = nullptr; }
        OPENSSL_cleanse(secret_.data(), secret_.size());
        return *this;
    }

    std::memset(secret_.data(), 0, 32);
    int bn_bytes = BN_num_bytes(sec.get());
    if (bn_bytes > 0 && bn_bytes <= 32) {
        BN_bn2bin(sec.get(), secret_.data() + (32 - bn_bytes));
    }
    rebuild_pkey();
    return *this;
}

// ---------------------------------------------------------------------------
// Low-S normalization (BIP-62)
// ---------------------------------------------------------------------------

bool ecdsa_normalize_s(std::vector<uint8_t>& der_sig) {
    uint8_t r[32], s[32];
    if (!der_to_compact(der_sig.data(), der_sig.size(), r, s)) return false;

    BN_ptr s_bn{BN_bin2bn(s, 32, nullptr)};
    if (!s_bn) return false;

    if (BN_cmp(s_bn.get(), secp256k1_half_order_bn()) > 0) {
        // s = n - s
        const BIGNUM* order = secp256k1_order_bn();
        BN_sub(s_bn.get(), order, s_bn.get());

        std::memset(s, 0, 32);
        int bn_bytes = BN_num_bytes(s_bn.get());
        if (bn_bytes > 0 && bn_bytes <= 32) {
            BN_bn2bin(s_bn.get(), s + (32 - bn_bytes));
        }

        der_sig = compact_to_der(r, s);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Pubkey validation
// ---------------------------------------------------------------------------

bool is_valid_pubkey(std::span<const uint8_t> pubkey) {
    if (pubkey.size() == 33) {
        if (pubkey[0] != 0x02 && pubkey[0] != 0x03) return false;
    } else if (pubkey.size() == 65) {
        if (pubkey[0] != 0x04) return false;
    } else {
        return false;
    }

    // Try to decode the point on the curve.
    EC_GROUP* grp = secp256k1_group();
    BN_CTX_ptr ctx{BN_CTX_new()};
    EC_PT_ptr pt{EC_POINT_new(grp)};
    if (!EC_POINT_oct2point(grp, pt.get(), pubkey.data(), pubkey.size(),
                            ctx.get())) {
        return false;
    }
    return EC_POINT_is_on_curve(grp, pt.get(), ctx.get()) == 1;
}

}  // namespace crypto
