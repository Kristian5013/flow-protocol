#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// P2P message framing for the FTC protocol.
//
// Wire format (little-endian):
//   Offset  Size  Field
//   0       4     magic        (0x46544321 = "FTC!")
//   4       12    command      (null-padded ASCII)
//   16      4     payload_size (bytes)
//   20      4     checksum     (first 4 bytes of Keccak-256 of payload)
//   24      N     payload      (raw bytes, N == payload_size)
//
// Total header size: 24 bytes.
// Maximum payload size: 32 MB.
// ---------------------------------------------------------------------------

#include "core/error.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace net {

// ===================================================================
// MessageHeader
// ===================================================================

struct MessageHeader {
    /// FTC network magic bytes: "FTC!" in ASCII.
    static constexpr uint32_t MAGIC = 0x46544321;

    /// Total header size on the wire (bytes).
    static constexpr size_t HEADER_SIZE = 24;

    /// Fixed width of the command field.
    static constexpr size_t COMMAND_SIZE = 12;

    /// Maximum allowed payload (32 MB).
    static constexpr size_t MAX_PAYLOAD_SIZE = 32 * 1024 * 1024;

    uint32_t magic = MAGIC;
    std::array<char, 12> command{};
    uint32_t payload_size = 0;
    uint32_t checksum = 0;

    /// Set the command field from a string_view (truncated + null-padded).
    void set_command(std::string_view cmd);

    /// Read the command field as a trimmed string (strips trailing nulls).
    [[nodiscard]] std::string get_command() const;

    /// Serialize the 24-byte header to a byte vector (little-endian).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a 24-byte header from raw bytes.
    [[nodiscard]] static core::Result<MessageHeader> deserialize(
        std::span<const uint8_t> data);
};

// ===================================================================
// Message
// ===================================================================

struct Message {
    MessageHeader header;
    std::vector<uint8_t> payload;

    /// Create a message with the given command and payload.
    /// Automatically computes the checksum and fills in header fields.
    [[nodiscard]] static Message create(std::string_view command,
                                        std::vector<uint8_t> payload);

    /// Compute the FTC checksum: first 4 bytes of Keccak-256(data).
    [[nodiscard]] static uint32_t compute_checksum(
        std::span<const uint8_t> data);

    /// Verify that the header checksum matches the payload.
    [[nodiscard]] bool verify_checksum() const;

    /// Serialize the complete message (header + payload) to bytes.
    [[nodiscard]] std::vector<uint8_t> serialize() const;
};

// ===================================================================
// Standard command names
// ===================================================================

namespace commands {
    inline constexpr const char* VERSION     = "version";
    inline constexpr const char* VERACK      = "verack";
    inline constexpr const char* ADDR        = "addr";
    inline constexpr const char* INV         = "inv";
    inline constexpr const char* GETDATA     = "getdata";
    inline constexpr const char* GETBLOCKS   = "getblocks";
    inline constexpr const char* GETHEADERS  = "getheaders";
    inline constexpr const char* TX          = "tx";
    inline constexpr const char* BLOCK       = "block";
    inline constexpr const char* HEADERS     = "headers";
    inline constexpr const char* GETADDR     = "getaddr";
    inline constexpr const char* PING        = "ping";
    inline constexpr const char* PONG        = "pong";
    inline constexpr const char* NOTFOUND    = "notfound";
    inline constexpr const char* SENDHEADERS = "sendheaders";
    inline constexpr const char* SENDCMPCT   = "sendcmpct";
    inline constexpr const char* CMPCTBLOCK  = "cmpctblock";
    inline constexpr const char* GETBLOCKTXN = "getblocktxn";
    inline constexpr const char* BLOCKTXN    = "blocktxn";
    inline constexpr const char* FEEFILTER   = "feefilter";
    inline constexpr const char* REJECT      = "reject";
} // namespace commands

} // namespace net
