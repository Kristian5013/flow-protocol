// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/version.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// Service flags helpers
// ===========================================================================

std::string service_flags_to_string(uint64_t flags) {
    if (flags == NODE_NONE) {
        return "NONE";
    }

    std::string result;

    auto append_flag = [&](uint64_t flag, const char* name) {
        if (flags & flag) {
            if (!result.empty()) {
                result += " | ";
            }
            result += name;
        }
    };

    append_flag(NODE_NETWORK,         "NODE_NETWORK");
    append_flag(NODE_WITNESS,         "NODE_WITNESS");
    append_flag(NODE_COMPACT_FILTERS, "NODE_COMPACT_FILTERS");
    append_flag(NODE_NETWORK_LIMITED, "NODE_NETWORK_LIMITED");

    // Check for any unknown bits that are set
    uint64_t known_mask = NODE_NETWORK | NODE_WITNESS
                        | NODE_COMPACT_FILTERS | NODE_NETWORK_LIMITED;
    uint64_t unknown = flags & ~known_mask;
    if (unknown != 0) {
        if (!result.empty()) {
            result += " | ";
        }
        result += "UNKNOWN(0x" + std::to_string(unknown) + ")";
    }

    return result;
}

// ===========================================================================
// VersionMessage -- serialization helpers
// ===========================================================================

namespace {

/// Write a network address (services + ip + port) to a stream.
/// Port is written in big-endian (network byte order) per the Bitcoin protocol.
template <typename Stream>
void write_net_addr(Stream& s,
                    uint64_t services,
                    const std::array<uint8_t, 16>& ip,
                    uint16_t port) {
    core::ser_write_u64(s, services);
    core::ser_write_bytes(s, std::span<const uint8_t>(ip.data(), ip.size()));
    // Port is always big-endian on the wire (network byte order)
    uint8_t port_be[2];
    port_be[0] = static_cast<uint8_t>((port >> 8) & 0xFF);
    port_be[1] = static_cast<uint8_t>(port & 0xFF);
    core::ser_write_bytes(s, std::span<const uint8_t>(port_be, 2));
}

/// Read a network address (services + ip + port) from a stream.
template <typename Stream>
void read_net_addr(Stream& s,
                   uint64_t& services,
                   std::array<uint8_t, 16>& ip,
                   uint16_t& port) {
    services = core::ser_read_u64(s);
    core::ser_read_bytes(s, std::span<uint8_t>(ip.data(), ip.size()));
    uint8_t port_be[2];
    core::ser_read_bytes(s, std::span<uint8_t>(port_be, 2));
    port = static_cast<uint16_t>(
        (static_cast<uint16_t>(port_be[0]) << 8) | port_be[1]);
}

} // anonymous namespace

// ===========================================================================
// VersionMessage serialization
// ===========================================================================

std::vector<uint8_t> VersionMessage::serialize() const {
    core::DataStream stream;

    // Pre-allocate: fixed fields (86) + user agent + compact_size overhead
    stream.reserve(86 + user_agent.size() + 5);

    // Protocol version (4 bytes LE)
    core::ser_write_i32(stream, version);

    // Services offered by the sender (8 bytes LE)
    core::ser_write_u64(stream, services);

    // Timestamp: standard Unix epoch seconds (8 bytes LE)
    core::ser_write_i64(stream, timestamp);

    // Address of the receiving node (without timestamp field, per spec)
    write_net_addr(stream, addr_recv_services, addr_recv_ip, addr_recv_port);

    // Address of the sending node
    write_net_addr(stream, addr_from_services, addr_from_ip, addr_from_port);

    // Random nonce used to detect self-connections (8 bytes LE)
    core::ser_write_u64(stream, nonce);

    // User agent string: compact-size length prefix followed by UTF-8 bytes
    core::ser_write_string(stream, user_agent);

    // Best block height known to the sender (4 bytes LE)
    core::ser_write_i32(stream, start_height);

    // Whether the sender wants to receive relay inv messages (BIP37).
    // This field was added in protocol version 70001.
    core::ser_write_bool(stream, relay);

    return stream.release();
}

// ===========================================================================
// VersionMessage deserialization
// ===========================================================================

core::Result<VersionMessage> VersionMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        // Minimum payload: everything through start_height (no relay byte, no
        // user_agent).  We do a coarse check before parsing.
        if (data.size() < 46) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "VersionMessage payload too short: "
                + std::to_string(data.size()) + " bytes (min ~85)");
        }

        core::SpanReader reader{data};
        VersionMessage msg;

        // Protocol version
        msg.version = core::ser_read_i32(reader);

        // Services
        msg.services = core::ser_read_u64(reader);

        // Timestamp
        msg.timestamp = core::ser_read_i64(reader);

        // Receiving node address
        read_net_addr(reader,
                      msg.addr_recv_services,
                      msg.addr_recv_ip,
                      msg.addr_recv_port);

        // Sending node address
        read_net_addr(reader,
                      msg.addr_from_services,
                      msg.addr_from_ip,
                      msg.addr_from_port);

        // Nonce
        msg.nonce = core::ser_read_u64(reader);

        // User agent string
        msg.user_agent = core::ser_read_string(reader);

        // Enforce user agent length limit
        if (msg.user_agent.size() > MAX_USER_AGENT_LENGTH) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "VersionMessage user_agent exceeds MAX_USER_AGENT_LENGTH ("
                + std::to_string(MAX_USER_AGENT_LENGTH) + ")");
        }

        // Start height
        msg.start_height = core::ser_read_i32(reader);

        // Relay flag -- optional field (added in BIP37, protocol >= 70001).
        // If not present, default to true.
        if (!reader.eof()) {
            msg.relay = core::ser_read_bool(reader);
        } else {
            msg.relay = true;
        }

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize VersionMessage: ") + e.what());
    }
}

// ===========================================================================
// VersionMessage validation
// ===========================================================================

core::Result<void> VersionMessage::validate() const {
    // Reject peers running a protocol version that is too old
    if (version < MIN_PEER_PROTO_VERSION) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "Peer protocol version " + std::to_string(version)
            + " is below minimum " + std::to_string(MIN_PEER_PROTO_VERSION));
    }

    // Reject absurdly long user agent strings
    if (user_agent.size() > MAX_USER_AGENT_LENGTH) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "User agent string too long: " + std::to_string(user_agent.size())
            + " bytes (max " + std::to_string(MAX_USER_AGENT_LENGTH) + ")");
    }

    // Sanity check on start_height: must be non-negative and within reason
    if (start_height < 0) {
        return core::Error(core::ErrorCode::VALIDATION_RANGE,
            "Negative start_height: " + std::to_string(start_height));
    }

    if (start_height > MAX_START_HEIGHT) {
        return core::Error(core::ErrorCode::VALIDATION_RANGE,
            "start_height " + std::to_string(start_height)
            + " exceeds MAX_START_HEIGHT (" + std::to_string(MAX_START_HEIGHT) + ")");
    }

    // Timestamp should not be too far in the future (2 hours tolerance)
    // This check is left to the caller since it requires the current time.

    return core::make_ok();
}

// ===========================================================================
// VersionMessage helpers
// ===========================================================================

bool VersionMessage::has_service(ServiceFlags flag) const noexcept {
    return (services & static_cast<uint64_t>(flag)) != 0;
}

// ===========================================================================
// VerackMessage serialization
// ===========================================================================

std::vector<uint8_t> VerackMessage::serialize() const {
    // VERACK carries no payload
    return {};
}

core::Result<VerackMessage> VerackMessage::deserialize(
    std::span<const uint8_t> data) {
    if (!data.empty()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
            "VerackMessage must have empty payload, got "
            + std::to_string(data.size()) + " bytes");
    }
    return VerackMessage{};
}

} // namespace net::protocol
