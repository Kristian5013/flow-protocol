// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// P2P message framing implementation.
//
// The FTC wire protocol uses a simple fixed-size header followed by a
// variable-length payload.  The header contains a 4-byte magic value
// for stream synchronization, a 12-byte null-padded command name, a
// 4-byte payload length, and a 4-byte checksum computed as the first
// 4 bytes of the Keccak-256 hash of the payload.
//
// All multi-byte integer fields are encoded in LITTLE-ENDIAN byte order
// on the wire.
// ---------------------------------------------------------------------------

#include "net/transport/message.h"
#include "core/logging.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cstring>

namespace net {

// ===================================================================
// Little-endian encoding / decoding helpers
// ===================================================================

namespace {

/// Write a 32-bit integer in little-endian byte order.
inline void write_le32(uint8_t* dst, uint32_t val) noexcept {
    dst[0] = static_cast<uint8_t>(val);
    dst[1] = static_cast<uint8_t>(val >> 8);
    dst[2] = static_cast<uint8_t>(val >> 16);
    dst[3] = static_cast<uint8_t>(val >> 24);
}

/// Read a 32-bit integer from little-endian byte order.
inline uint32_t read_le32(const uint8_t* src) noexcept {
    return static_cast<uint32_t>(src[0])
         | (static_cast<uint32_t>(src[1]) << 8)
         | (static_cast<uint32_t>(src[2]) << 16)
         | (static_cast<uint32_t>(src[3]) << 24);
}

/// Returns true if c is a valid command-name character (printable ASCII
/// excluding control characters).
inline bool is_valid_command_char(char c) noexcept {
    // Accept printable ASCII: space (0x20) through tilde (0x7E).
    // We also allow lowercase and uppercase letters, digits, etc.
    return c >= 0x20 && c <= 0x7E;
}

/// Build a human-readable hex representation of a 4-byte value for
/// error messages (e.g. "0x46544321").
std::string hex32(uint32_t val) {
    char buf[11]; // "0x" + 8 hex + '\0'
    std::snprintf(buf, sizeof(buf), "0x%08X", val);
    return std::string(buf);
}

} // anonymous namespace

// ===================================================================
// MessageHeader :: set_command / get_command
// ===================================================================

void MessageHeader::set_command(std::string_view cmd) {
    // Zero-fill the entire command field first, then copy the command
    // name.  This ensures proper null-padding for shorter names.
    command.fill('\0');

    size_t copy_len = std::min(cmd.size(), COMMAND_SIZE);
    std::memcpy(command.data(), cmd.data(), copy_len);
}

std::string MessageHeader::get_command() const {
    // Find the first null byte (or end of array) and return everything
    // before it as a std::string.
    const char* begin = command.data();
    const char* end   = std::find(command.begin(), command.end(), '\0');
    return std::string(begin, static_cast<size_t>(end - begin));
}

// ===================================================================
// MessageHeader :: serialize
// ===================================================================

std::vector<uint8_t> MessageHeader::serialize() const {
    std::vector<uint8_t> buf(HEADER_SIZE);

    // Bytes  0..3:   magic (little-endian)
    write_le32(buf.data(), magic);

    // Bytes  4..15:  command (12 bytes, null-padded)
    std::memcpy(buf.data() + 4, command.data(), COMMAND_SIZE);

    // Bytes 16..19:  payload_size (little-endian)
    write_le32(buf.data() + 16, payload_size);

    // Bytes 20..23:  checksum (little-endian)
    write_le32(buf.data() + 20, checksum);

    return buf;
}

// ===================================================================
// MessageHeader :: deserialize
// ===================================================================

core::Result<MessageHeader> MessageHeader::deserialize(
        std::span<const uint8_t> data) {
    // ------------------------------------------------------------------
    // Size check
    // ------------------------------------------------------------------
    if (data.size() < HEADER_SIZE) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "message header too short: need " +
                           std::to_string(HEADER_SIZE) + " bytes, got " +
                           std::to_string(data.size()));
    }

    MessageHeader hdr;

    // ------------------------------------------------------------------
    // Magic bytes
    // ------------------------------------------------------------------
    hdr.magic = read_le32(data.data());
    if (hdr.magic != MAGIC) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "invalid magic bytes: expected " +
                           hex32(MAGIC) + ", got " + hex32(hdr.magic));
    }

    // ------------------------------------------------------------------
    // Command field validation
    // ------------------------------------------------------------------
    std::memcpy(hdr.command.data(), data.data() + 4, COMMAND_SIZE);

    // The command field must consist of printable ASCII characters
    // followed by zero or more null-padding bytes.  Once the first null
    // byte is encountered, all remaining bytes must also be null.
    bool found_null = false;
    bool has_content = false;

    for (size_t i = 0; i < COMMAND_SIZE; ++i) {
        char c = hdr.command[i];
        if (found_null) {
            if (c != '\0') {
                return core::Error(core::ErrorCode::PARSE_ERROR,
                                   "command field has non-null byte after "
                                   "null padding at offset " +
                                   std::to_string(i));
            }
        } else if (c == '\0') {
            found_null = true;
        } else {
            if (!is_valid_command_char(c)) {
                return core::Error(core::ErrorCode::PARSE_ERROR,
                                   "invalid byte 0x" +
                                   ([c]{
                                       char h[3];
                                       std::snprintf(h, sizeof(h), "%02X",
                                                     static_cast<unsigned char>(c));
                                       return std::string(h);
                                   })() +
                                   " in command field at offset " +
                                   std::to_string(i));
            }
            has_content = true;
        }
    }

    // A completely empty command is invalid.
    if (!has_content) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "empty command name in message header");
    }

    // ------------------------------------------------------------------
    // Payload size
    // ------------------------------------------------------------------
    hdr.payload_size = read_le32(data.data() + 16);
    if (hdr.payload_size > MAX_PAYLOAD_SIZE) {
        return core::Error(core::ErrorCode::PARSE_ERROR,
                           "payload size " +
                           std::to_string(hdr.payload_size) +
                           " exceeds maximum allowed size " +
                           std::to_string(MAX_PAYLOAD_SIZE) +
                           " (" + std::to_string(MAX_PAYLOAD_SIZE / (1024 * 1024)) +
                           " MB)");
    }

    // ------------------------------------------------------------------
    // Checksum (stored as-is; validated later against the actual payload)
    // ------------------------------------------------------------------
    hdr.checksum = read_le32(data.data() + 20);

    return hdr;
}

// ===================================================================
// Message :: create
// ===================================================================

Message Message::create(std::string_view command,
                        std::vector<uint8_t> payload) {
    Message msg;
    msg.header.magic = MessageHeader::MAGIC;
    msg.header.set_command(command);
    msg.header.payload_size = static_cast<uint32_t>(payload.size());
    msg.header.checksum = compute_checksum(
        std::span<const uint8_t>(payload));
    msg.payload = std::move(payload);
    return msg;
}

// ===================================================================
// Message :: compute_checksum
// ===================================================================

uint32_t Message::compute_checksum(std::span<const uint8_t> data) {
    // FTC checksum definition:
    //   First 4 bytes of Keccak-256(payload), read as a little-endian
    //   uint32.
    //
    // This provides a fast integrity check on the wire.  It is NOT
    // a cryptographic commitment -- the full Keccak-256 hash should
    // be used when security is required.

    core::uint256 hash = crypto::keccak256(data);
    const uint8_t* h = hash.data();

    // The uint256 stores bytes in little-endian order internally.
    // We read the first 4 bytes as a LE uint32 to form the checksum.
    return static_cast<uint32_t>(h[0])
         | (static_cast<uint32_t>(h[1]) << 8)
         | (static_cast<uint32_t>(h[2]) << 16)
         | (static_cast<uint32_t>(h[3]) << 24);
}

// ===================================================================
// Message :: verify_checksum
// ===================================================================

bool Message::verify_checksum() const {
    uint32_t expected = compute_checksum(
        std::span<const uint8_t>(payload));
    if (header.checksum != expected) {
        LOG_TRACE(core::LogCategory::NET,
                  "checksum mismatch for '" + header.get_command() +
                  "': header=" + hex32(header.checksum) +
                  " computed=" + hex32(expected));
        return false;
    }
    return true;
}

// ===================================================================
// Message :: serialize
// ===================================================================

std::vector<uint8_t> Message::serialize() const {
    // Serialize the header, then append the payload.
    std::vector<uint8_t> hdr_bytes = header.serialize();

    std::vector<uint8_t> result;
    result.reserve(hdr_bytes.size() + payload.size());
    result.insert(result.end(), hdr_bytes.begin(), hdr_bytes.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

} // namespace net
