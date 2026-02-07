// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/protocol/addr.h"

#include "core/error.h"
#include "core/serialize.h"
#include "core/stream.h"

#include <algorithm>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace net::protocol {

// ===========================================================================
// AddressEntry serialization
// ===========================================================================

template <typename Stream>
void AddressEntry::serialize_to(Stream& s) const {
    // Timestamp: seconds since Unix epoch when this address was last seen
    core::ser_write_u32(s, timestamp);

    // Service flags advertised by the peer at this address
    core::ser_write_u64(s, services);

    // 16-byte IPv6 address (IPv4 addresses use ::ffff:x.x.x.x mapping)
    core::ser_write_bytes(s, std::span<const uint8_t>(ip.data(), ip.size()));

    // Port in big-endian (network byte order), matching Bitcoin wire format.
    // This is one of the few fields in the protocol that is NOT little-endian.
    uint8_t port_be[2];
    port_be[0] = static_cast<uint8_t>((port >> 8) & 0xFF);
    port_be[1] = static_cast<uint8_t>(port & 0xFF);
    core::ser_write_bytes(s, std::span<const uint8_t>(port_be, 2));
}

template <typename Stream>
AddressEntry AddressEntry::deserialize_from(Stream& s) {
    AddressEntry entry;

    entry.timestamp = core::ser_read_u32(s);
    entry.services  = core::ser_read_u64(s);

    // Read 16-byte IP address
    core::ser_read_bytes(s, std::span<uint8_t>(entry.ip.data(), entry.ip.size()));

    // Read port in big-endian (network byte order)
    uint8_t port_be[2];
    core::ser_read_bytes(s, std::span<uint8_t>(port_be, 2));
    entry.port = static_cast<uint16_t>(
        (static_cast<uint16_t>(port_be[0]) << 8) | port_be[1]);

    return entry;
}

// Explicit template instantiations for the stream types used in practice
template void AddressEntry::serialize_to<core::DataStream>(core::DataStream&) const;
template AddressEntry AddressEntry::deserialize_from<core::DataStream>(core::DataStream&);
template AddressEntry AddressEntry::deserialize_from<core::SpanReader>(core::SpanReader&);

// ===========================================================================
// AddressEntry helpers
// ===========================================================================

bool AddressEntry::is_ipv4() const noexcept {
    // An IPv4-mapped IPv6 address has the prefix ::ffff:0:0/96
    return std::equal(
        IPV4_MAPPED_PREFIX.begin(),
        IPV4_MAPPED_PREFIX.end(),
        ip.begin());
}

std::string AddressEntry::to_string() const {
    std::string result;

    if (is_ipv4()) {
        // Format as dotted-decimal IPv4
        result += std::to_string(ip[12]) + "."
                + std::to_string(ip[13]) + "."
                + std::to_string(ip[14]) + "."
                + std::to_string(ip[15]);
    } else {
        // Format as abbreviated IPv6 (simplified: full hex groups)
        result += "[";
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) result += ":";
            uint16_t group = (static_cast<uint16_t>(ip[i]) << 8) | ip[i + 1];
            // Simple hex formatting
            char buf[8];
            std::snprintf(buf, sizeof(buf), "%x", group);
            result += buf;
        }
        result += "]";
    }

    result += ":" + std::to_string(port);
    return result;
}

bool AddressEntry::is_routable() const noexcept {
    if (is_ipv4()) {
        // Check for non-routable IPv4 ranges
        uint8_t a = ip[12], b = ip[13];

        // 0.0.0.0/8 (current network)
        if (a == 0) return false;

        // 10.0.0.0/8 (private)
        if (a == 10) return false;

        // 127.0.0.0/8 (loopback)
        if (a == 127) return false;

        // 172.16.0.0/12 (private)
        if (a == 172 && (b >= 16 && b <= 31)) return false;

        // 192.168.0.0/16 (private)
        if (a == 192 && b == 168) return false;

        // 169.254.0.0/16 (link-local)
        if (a == 169 && b == 254) return false;

        // 224.0.0.0/4 (multicast)
        if (a >= 224) return false;

        return true;
    }

    // IPv6 routability checks

    // All zeros (unspecified address)
    bool all_zero = true;
    for (int i = 0; i < 16; ++i) {
        if (ip[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) return false;

    // ::1 (loopback)
    bool is_loopback = all_zero; // reuse the check for first 15 bytes
    if (!is_loopback) {
        is_loopback = true;
        for (int i = 0; i < 15; ++i) {
            if (ip[i] != 0) { is_loopback = false; break; }
        }
        if (is_loopback && ip[15] == 1) return false;
    }

    // fe80::/10 (link-local)
    if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return false;

    // fc00::/7 (unique local)
    if ((ip[0] & 0xFE) == 0xFC) return false;

    return true;
}

bool AddressEntry::operator==(const AddressEntry& other) const {
    return timestamp == other.timestamp
        && services  == other.services
        && ip        == other.ip
        && port      == other.port;
}

bool AddressEntry::operator!=(const AddressEntry& other) const {
    return !(*this == other);
}

// ===========================================================================
// AddrMessage serialization
// ===========================================================================

std::vector<uint8_t> AddrMessage::serialize() const {
    core::DataStream stream;
    // Each address entry is 30 bytes, plus compact size prefix
    stream.reserve(5 + addresses.size() * ADDR_ENTRY_SIZE);

    core::ser_write_compact_size(stream, addresses.size());
    for (const auto& addr : addresses) {
        addr.serialize_to(stream);
    }

    return stream.release();
}

// ===========================================================================
// AddrMessage deserialization
// ===========================================================================

core::Result<AddrMessage> AddrMessage::deserialize(
    std::span<const uint8_t> data) {
    try {
        core::SpanReader reader{data};
        AddrMessage msg;

        uint64_t count = core::ser_read_compact_size(reader);
        if (count > MAX_ADDR_ENTRIES) {
            return core::Error(core::ErrorCode::PARSE_OVERFLOW,
                "AddrMessage address count " + std::to_string(count)
                + " exceeds MAX_ADDR_ENTRIES ("
                + std::to_string(MAX_ADDR_ENTRIES) + ")");
        }

        // Verify that enough data remains for the declared count
        size_t needed = static_cast<size_t>(count) * ADDR_ENTRY_SIZE;
        if (reader.remaining() < needed) {
            return core::Error(core::ErrorCode::PARSE_UNDERFLOW,
                "AddrMessage: declared " + std::to_string(count)
                + " entries but only " + std::to_string(reader.remaining())
                + " bytes remain (need " + std::to_string(needed) + ")");
        }

        msg.addresses.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            msg.addresses.push_back(AddressEntry::deserialize_from(reader));
        }

        return msg;
    } catch (const std::exception& e) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
            std::string("Failed to deserialize AddrMessage: ") + e.what());
    }
}

// ===========================================================================
// AddrMessage validation
// ===========================================================================

core::Result<void> AddrMessage::validate() const {
    if (addresses.size() > MAX_ADDR_ENTRIES) {
        return core::Error(core::ErrorCode::VALIDATION_ERROR,
            "AddrMessage contains " + std::to_string(addresses.size())
            + " entries, exceeding MAX_ADDR_ENTRIES ("
            + std::to_string(MAX_ADDR_ENTRIES) + ")");
    }

    // Validate that timestamps are not wildly in the future
    // (we allow some slack; the caller should check against current time)
    for (size_t i = 0; i < addresses.size(); ++i) {
        if (addresses[i].port == 0) {
            return core::Error(core::ErrorCode::VALIDATION_RANGE,
                "AddrMessage: zero port at entry index " + std::to_string(i));
        }
    }

    return core::make_ok();
}

// ===========================================================================
// GetAddrMessage serialization
// ===========================================================================

std::vector<uint8_t> GetAddrMessage::serialize() const {
    // GETADDR carries no payload
    return {};
}

core::Result<GetAddrMessage> GetAddrMessage::deserialize(
    std::span<const uint8_t> data) {
    if (!data.empty()) {
        return core::Error(core::ErrorCode::PARSE_BAD_FORMAT,
            "GetAddrMessage must have empty payload, got "
            + std::to_string(data.size()) + " bytes");
    }
    return GetAddrMessage{};
}

} // namespace net::protocol
