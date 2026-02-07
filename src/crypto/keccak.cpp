// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/keccak.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace crypto {

// ===================================================================
// Internal helpers
// ===================================================================

namespace {

/// Perform a single SHA3-256 digest and write exactly 32 bytes into @p out.
void raw_keccak256(const void* data, size_t len, uint8_t* out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error(
            "keccak256: EVP_MD_CTX_new() allocation failed");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error(
            "keccak256: EVP_DigestInit_ex() failed");
    }

    if (len > 0) {
        if (EVP_DigestUpdate(ctx, data, len) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error(
                "keccak256: EVP_DigestUpdate() failed");
        }
    }

    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, out, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error(
            "keccak256: EVP_DigestFinal_ex() failed");
    }
    assert(digest_len == 32);

    EVP_MD_CTX_free(ctx);
}

/// Build a core::uint256 from a 32-byte raw digest buffer.
/// The bytes are stored directly (no endian conversion).
core::uint256 make_uint256(const uint8_t (&buf)[32]) {
    return core::uint256::from_bytes(
        std::span<const uint8_t, 32>(buf, 32));
}

/// Build a core::uint160 from the first 20 bytes of a 32-byte buffer.
core::uint160 make_uint160(const uint8_t (&buf)[32]) {
    return core::uint160::from_bytes(
        std::span<const uint8_t, 20>(buf, 20));
}

}  // namespace

// ===================================================================
// One-shot functions
// ===================================================================

core::uint256 keccak256(std::span<const uint8_t> data) {
    uint8_t buf[32];
    raw_keccak256(data.data(), data.size(), buf);
    return make_uint256(buf);
}

core::uint256 keccak256(const void* data, size_t len) {
    uint8_t buf[32];
    raw_keccak256(data, len, buf);
    return make_uint256(buf);
}

core::uint256 keccak256d(std::span<const uint8_t> data) {
    // First pass.
    uint8_t first[32];
    raw_keccak256(data.data(), data.size(), first);

    // Second pass: hash the first digest.
    uint8_t second[32];
    raw_keccak256(first, 32, second);

    return make_uint256(second);
}

core::uint160 hash160(std::span<const uint8_t> data) {
    // Double-hash, then truncate to 160 bits.
    uint8_t first[32];
    raw_keccak256(data.data(), data.size(), first);

    uint8_t second[32];
    raw_keccak256(first, 32, second);

    return make_uint160(second);
}

// ===================================================================
// Keccak256Hasher -- incremental interface
// ===================================================================

void Keccak256Hasher::init() {
    ctx_ = EVP_MD_CTX_new();
    if (!ctx_) {
        throw std::runtime_error(
            "Keccak256Hasher: EVP_MD_CTX_new() allocation failed");
    }
    if (EVP_DigestInit_ex(ctx_, EVP_sha3_256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx_);
        ctx_ = nullptr;
        throw std::runtime_error(
            "Keccak256Hasher: EVP_DigestInit_ex() failed");
    }
    finalized_ = false;
}

Keccak256Hasher::Keccak256Hasher() {
    init();
}

Keccak256Hasher::~Keccak256Hasher() {
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
    }
}

Keccak256Hasher::Keccak256Hasher(Keccak256Hasher&& other) noexcept
    : ctx_(other.ctx_), finalized_(other.finalized_) {
    other.ctx_ = nullptr;
    other.finalized_ = true;
}

Keccak256Hasher& Keccak256Hasher::operator=(
    Keccak256Hasher&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
        ctx_ = other.ctx_;
        finalized_ = other.finalized_;
        other.ctx_ = nullptr;
        other.finalized_ = true;
    }
    return *this;
}

Keccak256Hasher& Keccak256Hasher::write(
    std::span<const uint8_t> data) {
    if (!ctx_ || finalized_) {
        throw std::runtime_error(
            "Keccak256Hasher::write(): context not initialised "
            "or already finalised");
    }
    if (!data.empty()) {
        if (EVP_DigestUpdate(ctx_, data.data(), data.size()) != 1) {
            throw std::runtime_error(
                "Keccak256Hasher::write(): "
                "EVP_DigestUpdate() failed");
        }
    }
    return *this;
}

Keccak256Hasher& Keccak256Hasher::write(
    const void* data, size_t len) {
    return write(std::span<const uint8_t>(
        static_cast<const uint8_t*>(data), len));
}

core::uint256 Keccak256Hasher::finalize() {
    if (!ctx_ || finalized_) {
        throw std::runtime_error(
            "Keccak256Hasher::finalize(): context not initialised "
            "or already finalised");
    }

    uint8_t buf[32];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx_, buf, &digest_len) != 1) {
        throw std::runtime_error(
            "Keccak256Hasher::finalize(): "
            "EVP_DigestFinal_ex() failed");
    }
    assert(digest_len == 32);
    finalized_ = true;

    return make_uint256(buf);
}

void Keccak256Hasher::reset() {
    if (ctx_) {
        // Re-initialise the existing context -- avoids a free+alloc
        // round-trip.
        if (EVP_DigestInit_ex(ctx_, EVP_sha3_256(), nullptr) != 1) {
            throw std::runtime_error(
                "Keccak256Hasher::reset(): "
                "EVP_DigestInit_ex() failed");
        }
    } else {
        ctx_ = EVP_MD_CTX_new();
        if (!ctx_) {
            throw std::runtime_error(
                "Keccak256Hasher::reset(): "
                "EVP_MD_CTX_new() allocation failed");
        }
        if (EVP_DigestInit_ex(ctx_, EVP_sha3_256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx_);
            ctx_ = nullptr;
            throw std::runtime_error(
                "Keccak256Hasher::reset(): "
                "EVP_DigestInit_ex() failed");
        }
    }
    finalized_ = false;
}

// ===================================================================
// HMAC-Keccak256
// ===================================================================

std::array<uint8_t, 32> hmac_keccak256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data) {
    std::array<uint8_t, 32> result{};
    unsigned int out_len = 0;

    unsigned char* ret = HMAC(
        EVP_sha3_256(),
        key.data(),
        static_cast<int>(key.size()),
        data.data(),
        data.size(),
        result.data(),
        &out_len);

    if (!ret || out_len != 32) {
        throw std::runtime_error(
            "hmac_keccak256: HMAC() failed");
    }

    return result;
}

}  // namespace crypto
