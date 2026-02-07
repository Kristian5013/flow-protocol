#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// SipHash-2-4 -- fast, non-cryptographic keyed hash function.
//
// Used for hash-table randomisation, compact block relay short-IDs, and
// anywhere a fast keyed PRF is needed but collision resistance against an
// adaptive adversary is NOT required.
//
// Reference: Jean-Philippe Aumasson & Daniel J. Bernstein,
//            "SipHash: a fast short-input PRF" (2012).
//            https://131002.net/siphash/
// ---------------------------------------------------------------------------

#include "core/types.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto {

// ===================================================================
// SipHash-2-4 incremental hasher
// ===================================================================

class SipHash {
public:
    /// Initialise with a 128-bit key split into two 64-bit halves.
    SipHash(uint64_t k0, uint64_t k1);

    /// Feed an arbitrary byte span into the hash state.
    SipHash& write(std::span<const uint8_t> data);

    /// Feed a 64-bit value (little-endian) into the hash state.
    SipHash& write_u64(uint64_t val);

    /// Feed a 32-bit value (little-endian, zero-extended to 64 bits)
    /// into the hash state.
    SipHash& write_u32(uint32_t val);

    /// Produce the final 64-bit SipHash-2-4 digest.
    /// After this call the hasher state is consumed; do not call
    /// write() or finalize() again without constructing a new object.
    [[nodiscard]] uint64_t finalize();

private:
    /// Process a single 64-bit message word through two SipRounds.
    void compress(uint64_t m);

    uint64_t v0_;
    uint64_t v1_;
    uint64_t v2_;
    uint64_t v3_;

    /// Total number of bytes fed so far (mod 256).
    uint64_t count_ = 0;

    /// Accumulator for bytes not yet aligned to 8-byte blocks.
    uint64_t tmp_ = 0;
};

// ===================================================================
// Convenience one-shot functions
// ===================================================================

/// SipHash-2-4 of a uint256 value (hashes the raw 32 bytes).
[[nodiscard]] uint64_t siphash(
    uint64_t k0, uint64_t k1, const core::uint256& val);

/// SipHash-2-4 of an arbitrary byte span.
[[nodiscard]] uint64_t siphash(
    uint64_t k0, uint64_t k1, std::span<const uint8_t> data);

}  // namespace crypto
