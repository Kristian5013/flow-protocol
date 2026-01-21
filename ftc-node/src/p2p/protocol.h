#ifndef FTC_P2P_PROTOCOL_H
#define FTC_P2P_PROTOCOL_H

#include "crypto/keccak256.h"
#include "chain/block.h"
#include "chain/transaction.h"
#include "ftc/version.h"

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <variant>
#include <functional>

namespace ftc {
namespace p2p {

// ============================================================================
// Protocol Constants
// ============================================================================

constexpr uint32_t PROTOCOL_VERSION = 1;
constexpr uint32_t MAX_MESSAGE_SIZE = 4 * 1024 * 1024;  // 4 MB
constexpr uint32_t MAX_INV_SIZE = 50000;
constexpr uint32_t MAX_HEADERS_SIZE = 2000;
constexpr uint32_t MAX_ADDR_SIZE = 1000;
constexpr uint32_t MAX_LOCATOR_SIZE = 101;

// Service flags
constexpr uint64_t SERVICE_NONE = 0x00;
constexpr uint64_t SERVICE_FULL_NODE = 0x01;
constexpr uint64_t SERVICE_BLOOM = 0x02;

// ============================================================================
// Message Types
// ============================================================================

enum class MessageType : uint8_t {
    // Handshake
    VERSION = 0x00,
    VERACK = 0x01,

    // Heartbeat
    PING = 0x02,
    PONG = 0x03,

    // Error
    REJECT = 0x04,

    // Inventory
    INV = 0x10,
    GETDATA = 0x11,
    NOTFOUND = 0x12,

    // Blocks
    GETBLOCKS = 0x20,
    GETHEADERS = 0x21,
    HEADERS = 0x22,
    BLOCK = 0x23,

    // Transactions
    TX = 0x30,
    MEMPOOL = 0x31,

    // Peers
    GETADDR = 0x40,
    ADDR = 0x41,

    // Mining
    GETWORK = 0x50,
    SUBMITBLOCK = 0x51
};

const char* messageTypeName(MessageType type);

// ============================================================================
// Message Header (16 bytes)
// ============================================================================

#pragma pack(push, 1)
struct MessageHeader {
    uint32_t magic;           // Network magic (FTC_MAGIC_MAINNET)
    uint8_t type;             // MessageType
    uint8_t flags;            // Reserved
    uint16_t reserved;        // Reserved
    uint32_t payload_size;    // Payload size in bytes
    uint8_t checksum[4];      // First 4 bytes of Keccak256(payload)

    static constexpr size_t SIZE = 16;
    static constexpr size_t HEADER_SIZE = SIZE;  // Alias for compatibility

    bool isValid(uint32_t expected_magic) const;
    static MessageHeader create(uint32_t magic, MessageType type, uint32_t payload_size, const uint8_t* checksum);

    // Deserialize from raw bytes
    static bool deserialize(const uint8_t* data, size_t len, MessageHeader& out);
    bool deserialize(const uint8_t* data, size_t len);  // In-place version
};
#pragma pack(pop)

static_assert(sizeof(MessageHeader) == 16, "MessageHeader must be 16 bytes");

// Network magic for main network (alias for convenience)
constexpr uint32_t NETWORK_MAGIC = FTC_MAGIC_MAINNET;

// ============================================================================
// Inventory
// ============================================================================

enum class InvType : uint32_t {
    ERROR = 0,
    TX = 1,
    BLOCK = 2
};

struct InvItem {
    InvType type;
    crypto::Hash256 hash;

    bool operator==(const InvItem& other) const {
        return type == other.type && hash == other.hash;
    }

    std::vector<uint8_t> serialize() const;
    static std::optional<InvItem> deserialize(const uint8_t* data, size_t len, size_t& offset);
};

// ============================================================================
// Network Address
// ============================================================================

struct NetAddr {
    uint64_t services = SERVICE_FULL_NODE;
    uint8_t ip[16] = {0};     // IPv6 (or IPv4-mapped: ::ffff:x.x.x.x)
    uint16_t port = 0;
    uint32_t timestamp = 0;   // Unix timestamp when last seen

    NetAddr() = default;
    NetAddr(uint32_t ipv4, uint16_t port_, uint64_t services_ = SERVICE_FULL_NODE);
    NetAddr(const uint8_t* ipv6, uint16_t port_, uint64_t services_ = SERVICE_FULL_NODE);

    // Type checks
    bool isIPv4() const;
    bool isIPv6() const;
    bool isRoutable() const;
    bool isLocal() const;
    bool isRFC1918() const;     // Private IPv4 (10.x, 172.16-31.x, 192.168.x)
    bool isRFC4193() const;     // Private IPv6 (fc00::/7)

    // Accessors
    uint32_t getIPv4() const;
    std::string toString() const;

    // Factory methods
    static NetAddr fromIPv4(uint32_t ip, uint16_t port);
    static NetAddr fromIPv6(const uint8_t* ip, uint16_t port);
    static NetAddr fromString(const std::string& str);

    // Serialization
    std::vector<uint8_t> serialize(bool with_timestamp = true) const;
    static std::optional<NetAddr> deserialize(const uint8_t* data, size_t len, size_t& offset, bool with_timestamp = true);

    // Comparison
    bool operator==(const NetAddr& other) const;
    bool operator<(const NetAddr& other) const;
};

// NetAddrTime is an alias for NetAddr when timestamp field is significant
using NetAddrTime = NetAddr;

// ============================================================================
// VERSION Message
// ============================================================================

struct VersionMessage {
    uint32_t version = PROTOCOL_VERSION;
    uint64_t services = SERVICE_FULL_NODE;
    uint64_t timestamp = 0;
    NetAddr addr_recv;
    NetAddr addr_from;
    uint64_t nonce = 0;
    std::string user_agent = "/FTC:" FTC_VERSION_STRING "/";
    uint64_t start_height = 0;
    crypto::Hash256 best_hash = crypto::ZERO_HASH;
    bool relay = true;

    std::vector<uint8_t> serialize() const;
    static std::optional<VersionMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// VERACK Message (empty payload)
// ============================================================================

struct VerackMessage {
    std::vector<uint8_t> serialize() const { return {}; }
    static std::optional<VerackMessage> deserialize(const uint8_t*, size_t) { return VerackMessage{}; }
};

// ============================================================================
// PING / PONG Message
// ============================================================================

struct PingPongMessage {
    uint64_t nonce = 0;

    std::vector<uint8_t> serialize() const;
    static std::optional<PingPongMessage> deserialize(const uint8_t* data, size_t len);
};

// Type aliases for separate Ping/Pong messages
using PingMessage = PingPongMessage;
using PongMessage = PingPongMessage;

// ============================================================================
// REJECT Message
// ============================================================================

struct RejectMessage {
    MessageType message = MessageType::VERSION;
    uint8_t code = 0;
    std::string reason;
    crypto::Hash256 data = crypto::ZERO_HASH;

    enum RejectCode : uint8_t {
        REJECT_MALFORMED = 0x01,
        REJECT_INVALID = 0x10,
        REJECT_OBSOLETE = 0x11,
        REJECT_DUPLICATE = 0x12,
        REJECT_NONSTANDARD = 0x40,
        REJECT_DUST = 0x41,
        REJECT_INSUFFICIENTFEE = 0x42,
        REJECT_CHECKPOINT = 0x43
    };

    std::vector<uint8_t> serialize() const;
    static std::optional<RejectMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// INV / GETDATA / NOTFOUND Message
// ============================================================================

struct InvMessage {
    std::vector<InvItem> items;

    std::vector<uint8_t> serialize() const;
    static std::optional<InvMessage> deserialize(const uint8_t* data, size_t len);
};

using GetDataMessage = InvMessage;
using NotFoundMessage = InvMessage;

// ============================================================================
// GETBLOCKS Message
// ============================================================================

struct GetBlocksMessage {
    uint32_t version = PROTOCOL_VERSION;
    std::vector<crypto::Hash256> locator;  // Block locator (most recent first)
    crypto::Hash256 hash_stop = crypto::ZERO_HASH;  // Stop at this hash (0 = no limit)

    std::vector<uint8_t> serialize() const;
    static std::optional<GetBlocksMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// GETHEADERS Message
// ============================================================================

struct GetHeadersMessage {
    uint32_t version = PROTOCOL_VERSION;
    std::vector<crypto::Hash256> locator;
    crypto::Hash256 hash_stop = crypto::ZERO_HASH;

    std::vector<uint8_t> serialize() const;
    static std::optional<GetHeadersMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// HEADERS Message
// ============================================================================

struct HeadersMessage {
    std::vector<chain::BlockHeader> headers;

    std::vector<uint8_t> serialize() const;
    static std::optional<HeadersMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// BLOCK Message
// ============================================================================

struct BlockMessage {
    chain::Block block;

    std::vector<uint8_t> serialize() const;
    static std::optional<BlockMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// TX Message
// ============================================================================

struct TxMessage {
    chain::Transaction tx;

    std::vector<uint8_t> serialize() const;
    static std::optional<TxMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// MEMPOOL Message (empty)
// ============================================================================

struct MempoolMessage {
    std::vector<uint8_t> serialize() const { return {}; }
    static std::optional<MempoolMessage> deserialize(const uint8_t*, size_t) { return MempoolMessage{}; }
};

// ============================================================================
// GETADDR Message (empty)
// ============================================================================

struct GetAddrMessage {
    std::vector<uint8_t> serialize() const { return {}; }
    static std::optional<GetAddrMessage> deserialize(const uint8_t*, size_t) { return GetAddrMessage{}; }
};

// ============================================================================
// ADDR Message
// ============================================================================

struct AddrMessage {
    std::vector<NetAddr> addrs;

    std::vector<uint8_t> serialize() const;
    static std::optional<AddrMessage> deserialize(const uint8_t* data, size_t len);
};

// ============================================================================
// Message Wrapper
// ============================================================================

using MessagePayload = std::variant<
    VersionMessage,
    VerackMessage,
    PingPongMessage,
    RejectMessage,
    InvMessage,
    GetBlocksMessage,
    GetHeadersMessage,
    HeadersMessage,
    BlockMessage,
    TxMessage,
    MempoolMessage,
    GetAddrMessage,
    AddrMessage
>;

struct Message {
    MessageType type;
    MessagePayload payload;

    // Serialize with header
    std::vector<uint8_t> serialize(uint32_t magic) const;

    // Deserialize payload (after header is already parsed)
    bool deserializePayload(const uint8_t* data, size_t len);

    // Parse from raw data (returns message and bytes consumed)
    static std::optional<std::pair<Message, size_t>> parse(
        const uint8_t* data, size_t len, uint32_t expected_magic);
};

// ============================================================================
// Utilities
// ============================================================================

// Calculate checksum (first 4 bytes of Keccak256)
std::array<uint8_t, 4> calculateChecksum(const uint8_t* data, size_t len);

// Build block locator for chain sync
std::vector<crypto::Hash256> buildBlockLocator(
    uint64_t height,
    const std::function<crypto::Hash256(uint64_t)>& getHashAtHeight);

} // namespace p2p
} // namespace ftc

#endif // FTC_P2P_PROTOCOL_H
