// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/ping.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// PingMessage serialization
// ===========================================================================

std::vector<uint8_t> PingMessage::serialize() const {
    core::DataStream stream;
    stream.reserve(PING_PAYLOAD_SIZE);

    // Write the 8-byte random nonce in little-endian
    core::ser_write_u64(stream, nonce);

    return stream.release();
}

// ===========================================================================
// PingMessage deserialization
// ===========================================================================

core::Result<PingMessage> PingMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Handle legacy (pre-BIP31) ping messages that have no payload.
        // These were used in very old protocol versions (< 60001) and
        // carried no nonce.  We represent them with nonce=0.
        if (data.empty()) {
            return PingMessage{0};
        }

        // Modern ping messages must be exactly 8 bytes
        if (data.size() < PING_PAYLOAD_SIZE) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "PingMessage payload too short: expected "
                + std::to_string(PING_PAYLOAD_SIZE) + " bytes, got "
                + std::to_string(data.size()));
        }

        core::SpanReader reader{data};
        PingMessage msg;
        msg.nonce = core::ser_read_u64(reader);

        // Warn about extra trailing bytes but do not fail
        // (forward compatibility with future protocol extensions)

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize PingMessage: ") + e.what());
    }
}

// ===========================================================================
// PingMessage factory
// ===========================================================================

PingMessage PingMessage::with_nonce(uint64_t nonce_val) noexcept {
    PingMessage msg;
    msg.nonce = nonce_val;
    return msg;
}

// ===========================================================================
// PongMessage serialization
// ===========================================================================

std::vector<uint8_t> PongMessage::serialize() const {
    core::DataStream stream;
    stream.reserve(PING_PAYLOAD_SIZE);

    // Write the 8-byte nonce in little-endian (echo of the ping nonce)
    core::ser_write_u64(stream, nonce);

    return stream.release();
}

// ===========================================================================
// PongMessage deserialization
// ===========================================================================

core::Result<PongMessage> PongMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Pong messages always require the nonce field
        if (data.size() < PING_PAYLOAD_SIZE) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "PongMessage payload too short: expected "
                + std::to_string(PING_PAYLOAD_SIZE) + " bytes, got "
                + std::to_string(data.size()));
        }

        core::SpanReader reader{data};
        PongMessage msg;
        msg.nonce = core::ser_read_u64(reader);

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize PongMessage: ") + e.what());
    }
}

// ===========================================================================
// PongMessage factory
// ===========================================================================

PongMessage PongMessage::from_ping(const PingMessage& ping) noexcept {
    PongMessage msg;
    msg.nonce = ping.nonce;
    return msg;
}

} // namespace net::protocol
