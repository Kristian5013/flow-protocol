#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Higher-level hash utilities built on top of Keccak-256.
//
// Provides:
//   - hash<T>()     -- hash any Serializable object (double Keccak-256).
//   - HashWriter    -- stream adapter for incremental hash accumulation.
//   - tagged_hash() -- domain-separated tagged hashing (cf. BIP 340).
//   - hash_combine()-- combine two uint256 values for Merkle trees.
// ---------------------------------------------------------------------------

#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace crypto {

// ===================================================================
// Convenience: hash a Serializable object
// ===================================================================

/// Serialize @p obj into a temporary DataStream, then return
/// keccak256d (double Keccak-256) of the resulting byte sequence.
template <core::Serializable T>
[[nodiscard]] core::uint256 hash(const T& obj) {
    core::DataStream stream;
    obj.serialize(stream);
    auto view = stream.view();
    return keccak256d(view);
}

// ===================================================================
// HashWriter -- stream adapter for incremental hashing
// ===================================================================

/// Accumulates bytes written via the stream interface and produces a
/// Keccak-256 digest on demand.  Satisfies the write-side of the
/// Stream concept so it can be used directly with the serialization
/// framework.
class HashWriter {
public:
    HashWriter() = default;

    /// Append raw bytes to the internal buffer.
    void write(std::span<const uint8_t> data) {
        buf_.insert(buf_.end(), data.begin(), data.end());
    }

    /// Return the double Keccak-256 digest of all data written so far.
    /// Does NOT consume the buffer -- may be called repeatedly.
    [[nodiscard]] core::uint256 hash() const {
        return keccak256d(std::span<const uint8_t>(buf_));
    }

    /// Return the single Keccak-256 digest of all data written so far.
    /// Does NOT consume the buffer -- may be called repeatedly.
    [[nodiscard]] core::uint256 hash_single() const {
        return keccak256(std::span<const uint8_t>(buf_));
    }

    /// Return the number of bytes accumulated so far.
    [[nodiscard]] size_t size() const noexcept { return buf_.size(); }

    /// Reset the writer, discarding all accumulated data.
    void clear() { buf_.clear(); }

private:
    std::vector<uint8_t> buf_;
};

// ===================================================================
// Tagged hash
// ===================================================================

/// Domain-separated hash following the BIP-340 tagged-hash scheme
/// adapted for Keccak-256:
///
///   Keccak256( Keccak256(tag) || Keccak256(tag) || msg )
///
/// Prepending the double tag-hash creates a unique midstate per
/// domain, preventing cross-protocol hash collisions.
[[nodiscard]] core::uint256 tagged_hash(
    std::string_view tag,
    std::span<const uint8_t> msg);

// ===================================================================
// Hash combination (Merkle tree inner node)
// ===================================================================

/// Combine two 256-bit hashes by concatenating them and hashing the
/// 64-byte result with a single Keccak-256:
///
///   Keccak256( a.bytes() || b.bytes() )
///
/// Used as the inner-node combiner in Merkle tree constructions.
[[nodiscard]] core::uint256 hash_combine(
    const core::uint256& a,
    const core::uint256& b);

}  // namespace crypto
