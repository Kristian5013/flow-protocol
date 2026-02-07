// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block_header.h"

#include "core/serialize.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace primitives {

core::uint256 BlockHeader::hash() const {
    auto bytes = serialize_array();
    return crypto::keccak256d(
        std::span<const uint8_t>(bytes.data(), bytes.size()));
}

std::array<uint8_t, BlockHeader::SERIALIZED_SIZE>
BlockHeader::serialize_array() const {
    std::array<uint8_t, SERIALIZED_SIZE> buf{};
    size_t offset = 0;

    // Helper: write a 32-bit little-endian value at the current offset.
    auto write_u32 = [&](uint32_t v) {
        buf[offset + 0] = static_cast<uint8_t>(v & 0xFF);
        buf[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        buf[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        buf[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        offset += 4;
    };

    // Helper: write a 32-bit signed value as little-endian.
    auto write_i32 = [&](int32_t v) {
        write_u32(static_cast<uint32_t>(v));
    };

    // Helper: write 32 raw bytes from a uint256.
    auto write_uint256 = [&](const core::uint256& h) {
        std::memcpy(buf.data() + offset, h.data(), 32);
        offset += 32;
    };

    // version (4 bytes LE)
    write_i32(version);

    // prev_hash (32 bytes, raw internal representation)
    write_uint256(prev_hash);

    // merkle_root (32 bytes, raw internal representation)
    write_uint256(merkle_root);

    // timestamp (4 bytes LE)
    write_u32(timestamp);

    // bits (4 bytes LE)
    write_u32(bits);

    // nonce (4 bytes LE)
    write_u32(nonce);

    return buf;
}

bool BlockHeader::operator==(const BlockHeader& o) const {
    return version     == o.version
        && prev_hash   == o.prev_hash
        && merkle_root == o.merkle_root
        && timestamp   == o.timestamp
        && bits        == o.bits
        && nonce       == o.nonce;
}

} // namespace primitives
