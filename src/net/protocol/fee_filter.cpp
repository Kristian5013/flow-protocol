// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/fee_filter.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// FeeFilterMessage serialization
// ===========================================================================

std::vector<uint8_t> FeeFilterMessage::serialize() const {
    core::DataStream stream;
    stream.reserve(FEE_FILTER_PAYLOAD_SIZE);

    // Write the minimum fee rate as a signed 64-bit integer in little-endian.
    // The protocol uses int64 rather than uint64 for consistency with Bitcoin
    // Core's internal fee rate representation.
    core::ser_write_i64(stream, min_fee_rate);

    return stream.release();
}

// ===========================================================================
// FeeFilterMessage deserialization
// ===========================================================================

core::Result<FeeFilterMessage> FeeFilterMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        if (data.size() < FEE_FILTER_PAYLOAD_SIZE) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "FeeFilterMessage payload too short: expected "
                + std::to_string(FEE_FILTER_PAYLOAD_SIZE) + " bytes, got "
                + std::to_string(data.size()));
        }

        core::SpanReader reader{data};
        FeeFilterMessage msg;
        msg.min_fee_rate = core::ser_read_i64(reader);

        // Reject negative fee rates during deserialization.  A negative value
        // has no meaningful interpretation in the fee rate context and likely
        // indicates a malformed or malicious message.
        if (msg.min_fee_rate < 0) {
            return core::Error(core::ErrorCode::VALIDATION_RANGE,
                "FeeFilterMessage: negative fee rate ("
                + std::to_string(msg.min_fee_rate) + " sat/kvB)");
        }

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize FeeFilterMessage: ") + e.what());
    }
}

// ===========================================================================
// FeeFilterMessage validation
// ===========================================================================

core::Result<void> FeeFilterMessage::validate() const {
    // Fee rate must be non-negative
    if (min_fee_rate < 0) {
        return core::Error(core::ErrorCode::VALIDATION_RANGE,
            "FeeFilterMessage: negative fee rate ("
            + std::to_string(min_fee_rate) + " sat/kvB)");
    }

    // Reject absurdly high fee rates as a sanity check.
    // A rate of 1 BTC/kvB (100,000,000 sat/kvB) is already extreme.
    if (min_fee_rate > MAX_FEE_FILTER_RATE) {
        return core::Error(core::ErrorCode::VALIDATION_RANGE,
            "FeeFilterMessage: fee rate " + std::to_string(min_fee_rate)
            + " sat/kvB exceeds MAX_FEE_FILTER_RATE ("
            + std::to_string(MAX_FEE_FILTER_RATE) + ")");
    }

    return core::make_ok();
}

// ===========================================================================
// FeeFilterMessage helpers
// ===========================================================================

bool FeeFilterMessage::allows_all() const noexcept {
    return min_fee_rate == 0;
}

bool FeeFilterMessage::passes(int64_t tx_fee_rate) const noexcept {
    // A zero min_fee_rate means "accept all"
    if (min_fee_rate <= 0) return true;
    return tx_fee_rate >= min_fee_rate;
}

FeeFilterMessage FeeFilterMessage::with_rate(int64_t rate) noexcept {
    FeeFilterMessage msg;
    msg.min_fee_rate = rate;
    return msg;
}

} // namespace net::protocol
