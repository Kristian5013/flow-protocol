// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/hash.h"
#include "crypto/keccak.h"

#include <array>
#include <cstring>

namespace crypto {

// ===================================================================
// Tagged hash
// ===================================================================

core::uint256 tagged_hash(
    std::string_view tag,
    std::span<const uint8_t> msg) {
    // Compute the tag hash once: Keccak256(tag).
    core::uint256 tag_hash = keccak256(
        tag.data(), tag.size());

    // Build the pre-image: tag_hash || tag_hash || msg  (64 + msg.size())
    Keccak256Hasher hasher;
    hasher.write(std::span<const uint8_t>(
        tag_hash.data(), tag_hash.size()));
    hasher.write(std::span<const uint8_t>(
        tag_hash.data(), tag_hash.size()));
    hasher.write(msg);

    return hasher.finalize();
}

// ===================================================================
// Hash combination
// ===================================================================

core::uint256 hash_combine(
    const core::uint256& a,
    const core::uint256& b) {
    // Concatenate the two 32-byte values and hash.
    std::array<uint8_t, 64> combined;
    std::memcpy(combined.data(), a.data(), 32);
    std::memcpy(combined.data() + 32, b.data(), 32);

    return keccak256(std::span<const uint8_t>(combined));
}

}  // namespace crypto
