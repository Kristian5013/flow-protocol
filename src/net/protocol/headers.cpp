// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/headers.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"
#include "primitives/block_header.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// HeadersMessage serialization
// ===========================================================================

std::vector<uint8_t> HeadersMessage::serialize() const {
    core::DataStream stream;
    // Each header is 80 bytes + 1 byte for the zero tx_count = 81 bytes.
    // Plus a compact-size prefix for the count.
    stream.reserve(5 + headers.size() * HEADER_ENTRY_SIZE);

    // Write the number of headers
    core::ser_write_compact_size(stream, headers.size());

    for (const auto& header : headers) {
        // Serialize the 80-byte block header (version, prev_hash, merkle_root,
        // timestamp, bits, nonce)
        header.serialize(stream);

        // In the headers message, each header is followed by a transaction
        // count.  For the headers message specifically, this is always zero
        // because the message carries only headers, not full blocks.
        // This is a quirk of the Bitcoin protocol: the headers message
        // reuses the same serialization as blocks, but with zero txs.
        core::ser_write_compact_size(stream, 0);
    }

    return stream.release();
}

// ===========================================================================
// HeadersMessage deserialization
// ===========================================================================

core::Result<HeadersMessage> HeadersMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        core::SpanReader reader{data};
        HeadersMessage msg;

        uint64_t count = core::ser_read_compact_size(reader);
        if (count > MAX_HEADERS) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "HeadersMessage header count " + std::to_string(count)
                + " exceeds MAX_HEADERS (" + std::to_string(MAX_HEADERS) + ")");
        }

        // Verify sufficient data remains.  Each entry is exactly 81 bytes
        // (80-byte header + 1-byte zero compact_size).
        size_t needed = static_cast<size_t>(count) * HEADER_ENTRY_SIZE;
        if (reader.remaining() < needed) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "HeadersMessage: declared " + std::to_string(count)
                + " headers but only " + std::to_string(reader.remaining())
                + " bytes remain (need " + std::to_string(needed) + ")");
        }

        msg.headers.reserve(static_cast<size_t>(count));

        for (uint64_t i = 0; i < count; ++i) {
            // Deserialize the 80-byte block header
            auto header = primitives::BlockHeader::deserialize(reader);
            msg.headers.push_back(std::move(header));

            // Read and verify the transaction count that follows each header.
            // In a well-formed headers message this must always be zero.
            uint64_t tx_count = core::ser_read_compact_size(reader);
            if (tx_count != 0) {
                return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
                    "HeadersMessage: non-zero transaction count ("
                    + std::to_string(tx_count) + ") after header at index "
                    + std::to_string(i)
                    + " -- headers message must not contain transactions");
            }
        }

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize HeadersMessage: ") + e.what());
    }
}

// ===========================================================================
// HeadersMessage validation
// ===========================================================================

core::Result<void> HeadersMessage::validate() const {
    if (headers.size() > MAX_HEADERS) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "HeadersMessage contains " + std::to_string(headers.size())
            + " headers, exceeding MAX_HEADERS ("
            + std::to_string(MAX_HEADERS) + ")");
    }

    // Check chain continuity: each header's prev_hash should match the
    // hash of the preceding header in the list.  This is a structural
    // validation; full proof-of-work validation occurs elsewhere.
    for (size_t i = 1; i < headers.size(); ++i) {
        core::uint256 prev_computed = headers[i - 1].hash();
        if (!(headers[i].prev_hash == prev_computed)) {
            return core::Error(core::ErrorCode::VALIDATION_ERROR,
                "HeadersMessage: header at index " + std::to_string(i)
                + " has prev_hash " + headers[i].prev_hash.to_hex()
                + " but preceding header hashes to "
                + prev_computed.to_hex());
        }
    }

    // Verify that timestamps are monotonically non-decreasing (soft check).
    // The actual median-time-past rule is checked in consensus validation.
    // We skip this check here since it requires additional context.

    return core::make_ok();
}

bool HeadersMessage::is_full() const noexcept {
    return headers.size() == MAX_HEADERS;
}

// ===========================================================================
// GetHeadersMessage serialization
// ===========================================================================

std::vector<uint8_t> GetHeadersMessage::serialize() const {
    core::DataStream stream;
    // version (4) + compact_size (up to 9) + N * 32 + hash_stop (32)
    stream.reserve(4 + 9 + locator_hashes.size() * 32 + 32);

    // Protocol version
    core::ser_write_u32(stream, version);

    // Locator hash count
    core::ser_write_compact_size(stream, locator_hashes.size());

    // Locator hashes: ordered from the tip backwards with exponentially
    // increasing gaps (1, 1, 2, 4, 8, ...) to efficiently cover any chain
    // length with at most ~101 entries.
    for (const auto& hash : locator_hashes) {
        core::ser_write_uint256(stream, hash);
    }

    // Hash of the last desired header.  Zero means "send maximum headers".
    core::ser_write_uint256(stream, hash_stop);

    return stream.release();
}

// ===========================================================================
// GetHeadersMessage deserialization
// ===========================================================================

core::Result<GetHeadersMessage> GetHeadersMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Minimum: version (4) + compact_size(0) (1) + hash_stop (32) = 37
        if (data.size() < 37) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "GetHeadersMessage payload too short: "
                + std::to_string(data.size()) + " bytes (min 37)");
        }

        core::SpanReader reader{data};
        GetHeadersMessage msg;

        msg.version = core::ser_read_u32(reader);

        uint64_t count = core::ser_read_compact_size(reader);
        if (count > MAX_GETHEADERS_LOCATOR) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "GetHeadersMessage locator count " + std::to_string(count)
                + " exceeds MAX_GETHEADERS_LOCATOR ("
                + std::to_string(MAX_GETHEADERS_LOCATOR) + ")");
        }

        // Verify sufficient remaining bytes for locators + hash_stop
        size_t needed = static_cast<size_t>(count) * 32 + 32;
        if (reader.remaining() < needed) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "GetHeadersMessage: insufficient data for "
                + std::to_string(count) + " locator hashes plus hash_stop");
        }

        msg.locator_hashes.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            msg.locator_hashes.push_back(core::ser_read_uint256(reader));
        }

        msg.hash_stop = core::ser_read_uint256(reader);

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize GetHeadersMessage: ") + e.what());
    }
}

// ===========================================================================
// GetHeadersMessage validation
// ===========================================================================

core::Result<void> GetHeadersMessage::validate() const {
    if (locator_hashes.size() > MAX_GETHEADERS_LOCATOR) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "GetHeadersMessage: locator contains "
            + std::to_string(locator_hashes.size()) + " hashes (max "
            + std::to_string(MAX_GETHEADERS_LOCATOR) + ")");
    }

    return core::make_ok();
}

bool GetHeadersMessage::requests_maximum() const noexcept {
    return hash_stop.is_zero();
}

// ===========================================================================
// SendHeadersMessage serialization
// ===========================================================================

std::vector<uint8_t> SendHeadersMessage::serialize() const {
    // SENDHEADERS carries no payload
    return {};
}

core::Result<SendHeadersMessage> SendHeadersMessage::deserialize(
    std::span<const uint8_t> data) {
    if (!data.empty()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
            "SendHeadersMessage must have empty payload, got "
            + std::to_string(data.size()) + " bytes");
    }
    return SendHeadersMessage{};
}

} // namespace net::protocol
