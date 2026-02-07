#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/serialize.h"
#include "core/types.h"

#include <array>
#include <cstdint>

namespace primitives {

// ---------------------------------------------------------------------------
// BlockHeader -- 80-byte block header
// ---------------------------------------------------------------------------
// Layout (all fields little-endian):
//   version      (4 bytes)   -- block version
//   prev_hash    (32 bytes)  -- hash of previous block header
//   merkle_root  (32 bytes)  -- merkle root of transactions
//   timestamp    (4 bytes)   -- Unix epoch seconds
//   bits         (4 bytes)   -- compact difficulty target (nBits)
//   nonce        (4 bytes)   -- proof-of-work nonce
//                ----------
//                80 bytes total
// ---------------------------------------------------------------------------
class BlockHeader {
public:
    static constexpr size_t SERIALIZED_SIZE = 80;

    int32_t version = 1;
    core::uint256 prev_hash;
    core::uint256 merkle_root;
    uint32_t timestamp = 0;
    uint32_t bits = 0;
    uint32_t nonce = 0;

    BlockHeader() = default;

    /// Compute the block hash: keccak256d of the 80-byte serialized header.
    [[nodiscard]] core::uint256 hash() const;

    /// Serialize the header into a fixed 80-byte array.
    [[nodiscard]] std::array<uint8_t, SERIALIZED_SIZE> serialize_array() const;

    /// Serialize the header to an arbitrary stream.
    template <typename Stream>
    void serialize(Stream& s) const;

    /// Deserialize a header from an arbitrary stream.
    template <typename Stream>
    static BlockHeader deserialize(Stream& s);

    [[nodiscard]] bool operator==(const BlockHeader& o) const;
};

// =========================================================================
// Template implementations
// =========================================================================

template <typename Stream>
void BlockHeader::serialize(Stream& s) const {
    core::ser_write_i32(s, version);
    core::ser_write_uint256(s, prev_hash);
    core::ser_write_uint256(s, merkle_root);
    core::ser_write_u32(s, timestamp);
    core::ser_write_u32(s, bits);
    core::ser_write_u32(s, nonce);
}

template <typename Stream>
BlockHeader BlockHeader::deserialize(Stream& s) {
    BlockHeader h;
    h.version     = core::ser_read_i32(s);
    h.prev_hash   = core::ser_read_uint256(s);
    h.merkle_root = core::ser_read_uint256(s);
    h.timestamp   = core::ser_read_u32(s);
    h.bits        = core::ser_read_u32(s);
    h.nonce       = core::ser_read_u32(s);
    return h;
}

} // namespace primitives
