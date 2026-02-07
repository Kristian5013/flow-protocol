// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/inventory.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// InvType helpers
// ===========================================================================

const char* inv_type_name(InvType type) noexcept {
    switch (type) {
        case InvType::TX:             return "TX";
        case InvType::BLOCK:          return "BLOCK";
        case InvType::FILTERED_BLOCK: return "FILTERED_BLOCK";
        case InvType::CMPCT_BLOCK:    return "CMPCT_BLOCK";
        case InvType::WITNESS_TX:     return "WITNESS_TX";
        case InvType::WITNESS_BLOCK:  return "WITNESS_BLOCK";
        default:                      return "UNKNOWN";
    }
}

// ===========================================================================
// InvItem
// ===========================================================================

bool InvItem::operator==(const InvItem& other) const {
    return type == other.type && hash == other.hash;
}

bool InvItem::operator!=(const InvItem& other) const {
    return !(*this == other);
}

std::string InvItem::to_string() const {
    return std::string(inv_type_name(type)) + "(" + hash.to_hex() + ")";
}

template <typename Stream>
void InvItem::serialize_to(Stream& s) const {
    core::ser_write_u32(s, static_cast<uint32_t>(type));
    core::ser_write_uint256(s, hash);
}

template <typename Stream>
InvItem InvItem::deserialize_from(Stream& s) {
    InvItem item;
    uint32_t raw_type = core::ser_read_u32(s);
    item.type = static_cast<InvType>(raw_type);
    item.hash = core::ser_read_uint256(s);
    return item;
}

// Explicit template instantiations for the stream types used in practice
template void InvItem::serialize_to<core::DataStream>(core::DataStream&) const;
template InvItem InvItem::deserialize_from<core::DataStream>(core::DataStream&);
template InvItem InvItem::deserialize_from<core::SpanReader>(core::SpanReader&);

// ===========================================================================
// InvMessage serialization
// ===========================================================================

std::vector<uint8_t> InvMessage::serialize() const {
    core::DataStream stream;
    // Each inv item is 36 bytes (4 type + 32 hash), plus compact size prefix
    stream.reserve(5 + items.size() * 36);

    core::ser_write_compact_size(stream, items.size());
    for (const auto& item : items) {
        item.serialize_to(stream);
    }

    return stream.release();
}

// ===========================================================================
// InvMessage deserialization
// ===========================================================================

core::Result<InvMessage> InvMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        core::SpanReader reader{data};
        InvMessage msg;

        uint64_t count = core::ser_read_compact_size(reader);
        if (count > MAX_INV_ITEMS) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "InvMessage item count " + std::to_string(count)
                + " exceeds MAX_INV_ITEMS (" + std::to_string(MAX_INV_ITEMS) + ")");
        }

        // Verify that there are enough bytes remaining for the declared count.
        // Each item is exactly 36 bytes (4 + 32).
        size_t needed = static_cast<size_t>(count) * 36;
        if (reader.remaining() < needed) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "InvMessage: declared " + std::to_string(count)
                + " items but only " + std::to_string(reader.remaining())
                + " bytes remain (need " + std::to_string(needed) + ")");
        }

        msg.items.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            msg.items.push_back(InvItem::deserialize_from(reader));
        }

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize InvMessage: ") + e.what());
    }
}

// ===========================================================================
// InvMessage validation
// ===========================================================================

core::Result<void> InvMessage::validate() const {
    if (items.size() > MAX_INV_ITEMS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "InvMessage contains " + std::to_string(items.size())
            + " items, exceeding MAX_INV_ITEMS ("
            + std::to_string(MAX_INV_ITEMS) + ")");
    }

    // Validate each item's type is within the known range
    for (size_t i = 0; i < items.size(); ++i) {
        const auto& item = items[i];
        InvType base = inv_base_type(item.type);

        // The base type must be one of the recognized values
        bool known = (base == InvType::TX
                   || base == InvType::BLOCK
                   || base == InvType::FILTERED_BLOCK
                   || base == InvType::CMPCT_BLOCK);

        if (!known) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "InvMessage: unknown inventory type "
                + std::to_string(static_cast<uint32_t>(item.type))
                + " at index " + std::to_string(i));
        }

        // Reject items with a zero hash (meaningless reference)
        if (item.hash.is_zero()) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "InvMessage: zero hash at index " + std::to_string(i));
        }
    }

    return core::make_ok();
}

} // namespace net::protocol
