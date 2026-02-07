#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Keccak-256 (SHA3-256) wrapper around OpenSSL 3.0+ EVP API.
//
// All functions in this header produce deterministic, standards-compliant
// SHA3-256 digests.  The "keccak256" naming follows Ethereum convention;
// the underlying primitive is NIST SHA3-256 (FIPS 202).
// ---------------------------------------------------------------------------

#include "core/types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

// Forward-declare the OpenSSL context type so callers do not need the
// OpenSSL headers just to include this header.
struct evp_md_ctx_st;       // EVP_MD_CTX
typedef struct evp_md_ctx_st EVP_MD_CTX;

namespace crypto {

// ===================================================================
// One-shot hash functions
// ===================================================================

/// Compute Keccak-256 (SHA3-256) of a byte span.
[[nodiscard]] core::uint256 keccak256(std::span<const uint8_t> data);

/// Compute Keccak-256 (SHA3-256) of an arbitrary memory region.
[[nodiscard]] core::uint256 keccak256(const void* data, size_t len);

/// Double Keccak-256: Keccak256(Keccak256(data)).
/// Used as the standard hash-for-consensus throughout the protocol.
[[nodiscard]] core::uint256 keccak256d(std::span<const uint8_t> data);

/// Hash160: first 20 bytes of Keccak256(Keccak256(data)).
/// Used for address derivation.
[[nodiscard]] core::uint160 hash160(std::span<const uint8_t> data);

// ===================================================================
// Incremental hasher (streaming interface)
// ===================================================================

/// Move-only incremental Keccak-256 hasher backed by an OpenSSL
/// EVP_MD_CTX.  Feed data with write(), obtain the digest with
/// finalize().  Call reset() to reuse the object for another hash.
class Keccak256Hasher {
public:
    Keccak256Hasher();
    ~Keccak256Hasher();

    // Non-copyable.
    Keccak256Hasher(const Keccak256Hasher&) = delete;
    Keccak256Hasher& operator=(const Keccak256Hasher&) = delete;

    // Movable.
    Keccak256Hasher(Keccak256Hasher&& other) noexcept;
    Keccak256Hasher& operator=(Keccak256Hasher&& other) noexcept;

    /// Feed bytes into the running hash state.
    Keccak256Hasher& write(std::span<const uint8_t> data);

    /// Feed an arbitrary memory region into the running hash state.
    Keccak256Hasher& write(const void* data, size_t len);

    /// Produce the final 32-byte digest.  After this call the internal
    /// context is consumed; call reset() before hashing again.
    [[nodiscard]] core::uint256 finalize();

    /// Re-initialise the context so the hasher can be reused.
    void reset();

private:
    void init();

    EVP_MD_CTX* ctx_ = nullptr;
    bool finalized_ = false;
};

// ===================================================================
// HMAC-Keccak256
// ===================================================================

/// Compute HMAC-SHA3-256 (HMAC-Keccak256) of @p data keyed with @p key.
[[nodiscard]] std::array<uint8_t, 32> hmac_keccak256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data);

}  // namespace crypto
