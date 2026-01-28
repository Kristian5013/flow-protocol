#include "p2p/protocol.h"
#include "chain/transaction.h"
#include "util/time.h"

#include <cstring>
#include <sstream>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

namespace ftc {
namespace p2p {

// ============================================================================
// Utilities
// ============================================================================

const char* messageTypeName(MessageType type) {
    switch (type) {
        case MessageType::VERSION: return "VERSION";
        case MessageType::VERACK: return "VERACK";
        case MessageType::PING: return "PING";
        case MessageType::PONG: return "PONG";
        case MessageType::REJECT: return "REJECT";
        case MessageType::INV: return "INV";
        case MessageType::GETDATA: return "GETDATA";
        case MessageType::NOTFOUND: return "NOTFOUND";
        case MessageType::GETBLOCKS: return "GETBLOCKS";
        case MessageType::GETHEADERS: return "GETHEADERS";
        case MessageType::HEADERS: return "HEADERS";
        case MessageType::BLOCK: return "BLOCK";
        case MessageType::TX: return "TX";
        case MessageType::MEMPOOL: return "MEMPOOL";
        case MessageType::GETADDR: return "GETADDR";
        case MessageType::ADDR: return "ADDR";
        case MessageType::GETWORK: return "GETWORK";
        case MessageType::SUBMITBLOCK: return "SUBMITBLOCK";
        default: return "UNKNOWN";
    }
}

std::array<uint8_t, 4> calculateChecksum(const uint8_t* data, size_t len) {
    auto hash = crypto::Keccak256::hash(data, len);
    std::array<uint8_t, 4> checksum;
    std::memcpy(checksum.data(), hash.data(), 4);
    return checksum;
}

// Helper: write uint16 little-endian
static void writeU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(v & 0xFF);
    out.push_back((v >> 8) & 0xFF);
}

// Helper: write uint32 little-endian
static void writeU32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(v & 0xFF);
    out.push_back((v >> 8) & 0xFF);
    out.push_back((v >> 16) & 0xFF);
    out.push_back((v >> 24) & 0xFF);
}

// Helper: write uint64 little-endian
static void writeU64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        out.push_back((v >> (i * 8)) & 0xFF);
    }
}

// Helper: read uint16 little-endian
static uint16_t readU16(const uint8_t* data) {
    return data[0] | (static_cast<uint16_t>(data[1]) << 8);
}

// Helper: read uint32 little-endian
static uint32_t readU32(const uint8_t* data) {
    return data[0] |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

// Helper: read uint64 little-endian
static uint64_t readU64(const uint8_t* data) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return v;
}

// Helper: write varint
static void writeVarint(std::vector<uint8_t>& out, uint64_t v) {
    auto encoded = chain::varint::encode(v);
    out.insert(out.end(), encoded.begin(), encoded.end());
}

// Helper: write string (varint length + data)
static void writeString(std::vector<uint8_t>& out, const std::string& s) {
    writeVarint(out, s.size());
    out.insert(out.end(), s.begin(), s.end());
}

// Helper: read string
static std::optional<std::string> readString(const uint8_t* data, size_t len, size_t& offset) {
    auto length = chain::varint::decode(data, len, offset);
    if (!length || offset + *length > len) return std::nullopt;

    std::string s(reinterpret_cast<const char*>(data + offset), *length);
    offset += *length;
    return s;
}

// ============================================================================
// MessageHeader
// ============================================================================

bool MessageHeader::isValid(uint32_t expected_magic) const {
    if (magic != expected_magic) return false;
    if (payload_size > MAX_MESSAGE_SIZE) return false;
    return true;
}

MessageHeader MessageHeader::create(uint32_t magic, MessageType type, uint32_t payload_size, const uint8_t* checksum) {
    MessageHeader hdr;
    hdr.magic = magic;
    hdr.type = static_cast<uint8_t>(type);
    hdr.flags = 0;
    hdr.reserved = 0;
    hdr.payload_size = payload_size;
    std::memcpy(hdr.checksum, checksum, 4);
    return hdr;
}

bool MessageHeader::deserialize(const uint8_t* data, size_t len, MessageHeader& out) {
    if (len < SIZE) return false;
    std::memcpy(&out, data, SIZE);
    return true;
}

bool MessageHeader::deserialize(const uint8_t* data, size_t len) {
    return MessageHeader::deserialize(data, len, *this);
}

// ============================================================================
// InvItem
// ============================================================================

std::vector<uint8_t> InvItem::serialize() const {
    std::vector<uint8_t> out;
    writeU32(out, static_cast<uint32_t>(type));
    out.insert(out.end(), hash.begin(), hash.end());
    return out;
}

std::optional<InvItem> InvItem::deserialize(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 36 > len) return std::nullopt;

    InvItem item;
    item.type = static_cast<InvType>(readU32(data + offset));
    offset += 4;
    std::memcpy(item.hash.data(), data + offset, 32);
    offset += 32;
    return item;
}

// ============================================================================
// NetAddr
// ============================================================================

NetAddr::NetAddr(const uint8_t* ipv6, uint16_t port_, uint64_t services_)
    : services(services_), port(port_), timestamp(0) {
    std::memcpy(ip, ipv6, 16);
}

std::string NetAddr::toString() const {
    std::ostringstream oss;
    if (isIPv4()) {
        // IPv4 format: x.x.x.x:port
        oss << (int)ip[12] << "." << (int)ip[13] << "." << (int)ip[14] << "." << (int)ip[15];
        oss << ":" << port;
    } else {
        // IPv6 format: [xxxx::xxxx]:port
        oss << "[";
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) oss << ":";
            oss << std::hex << ((ip[i] << 8) | ip[i + 1]);
        }
        oss << std::dec << "]:" << port;
    }
    return oss.str();
}

std::vector<uint8_t> NetAddr::serialize(bool with_timestamp) const {
    std::vector<uint8_t> out;
    if (with_timestamp) {
        writeU32(out, timestamp);
    }
    writeU64(out, services);
    out.insert(out.end(), ip, ip + 16);
    writeU16(out, port);
    return out;
}

std::optional<NetAddr> NetAddr::deserialize(const uint8_t* data, size_t len, size_t& offset, bool with_timestamp) {
    size_t required = with_timestamp ? 30 : 26;
    if (offset + required > len) return std::nullopt;

    NetAddr addr;
    if (with_timestamp) {
        addr.timestamp = readU32(data + offset);
        offset += 4;
    }
    addr.services = readU64(data + offset);
    offset += 8;
    std::memcpy(addr.ip, data + offset, 16);
    offset += 16;
    addr.port = readU16(data + offset);
    offset += 2;

    return addr;
}

bool NetAddr::isLocal() const {
    // IPv6 localhost: ::1
    static const uint8_t ipv6_localhost[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
    return std::memcmp(ip, ipv6_localhost, 16) == 0;
}

bool NetAddr::isRFC4193() const {
    // fc00::/7 - Unique local addresses
    return (ip[0] & 0xfe) == 0xfc;
}

bool NetAddr::isIPv4() const {
    // IPv4-mapped IPv6: ::ffff:x.x.x.x
    // First 10 bytes are 0, next 2 bytes are 0xff
    static const uint8_t ipv4_mapped_prefix[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
    return std::memcmp(ip, ipv4_mapped_prefix, 12) == 0;
}

bool NetAddr::isIPv6() const {
    return !isIPv4();
}

bool NetAddr::isRoutable() const {
    if (isLocal()) return false;
    if (isRFC4193()) return false;

    // fe80::/10 - Link-local
    if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) return false;
    // ff00::/8 - Multicast
    if (ip[0] == 0xff) return false;
    // :: - Unspecified
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
        if (ip[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) return false;

    return true;
}

NetAddr NetAddr::fromIPv6(const uint8_t* ipv6, uint16_t port) {
    NetAddr addr;
    std::memcpy(addr.ip, ipv6, 16);
    addr.port = port;
    return addr;
}

NetAddr NetAddr::fromIPv4(const uint8_t* ip4, uint16_t port) {
    NetAddr addr;
    // IPv4-mapped IPv6: ::ffff:x.x.x.x
    std::memset(addr.ip, 0, 10);
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    std::memcpy(addr.ip + 12, ip4, 4);
    addr.port = port;
    return addr;
}

NetAddr NetAddr::fromIPv4(uint32_t ip4, uint16_t port) {
    NetAddr addr;
    // IPv4-mapped IPv6: ::ffff:x.x.x.x
    std::memset(addr.ip, 0, 10);
    addr.ip[10] = 0xff;
    addr.ip[11] = 0xff;
    // Network byte order (big endian)
    addr.ip[12] = (ip4 >> 24) & 0xff;
    addr.ip[13] = (ip4 >> 16) & 0xff;
    addr.ip[14] = (ip4 >> 8) & 0xff;
    addr.ip[15] = ip4 & 0xff;
    addr.port = port;
    return addr;
}

NetAddr NetAddr::fromString(const std::string& str) {
    NetAddr addr;
    std::memset(&addr, 0, sizeof(addr));

    // IPv6 format: [xxxx::xxxx]:port
    if (!str.empty() && str.front() == '[') {
        size_t bracketEnd = str.find(']');
        if (bracketEnd != std::string::npos) {
            std::string ip_part = str.substr(1, bracketEnd - 1);
            size_t colonPos = str.find(':', bracketEnd);
            if (colonPos != std::string::npos) {
                addr.port = static_cast<uint16_t>(std::stoi(str.substr(colonPos + 1)));
            }
            struct in6_addr ipv6;
            if (inet_pton(AF_INET6, ip_part.c_str(), &ipv6) == 1) {
                std::memcpy(addr.ip, &ipv6, 16);
            }
        }
    } else {
        // IPv4 format: x.x.x.x:port
        size_t colonPos = str.rfind(':');
        if (colonPos != std::string::npos) {
            std::string ip_part = str.substr(0, colonPos);
            addr.port = static_cast<uint16_t>(std::stoi(str.substr(colonPos + 1)));
            struct in_addr ipv4;
            if (inet_pton(AF_INET, ip_part.c_str(), &ipv4) == 1) {
                // Convert to IPv4-mapped IPv6
                std::memset(addr.ip, 0, 10);
                addr.ip[10] = 0xff;
                addr.ip[11] = 0xff;
                std::memcpy(addr.ip + 12, &ipv4, 4);
            }
        }
    }
    return addr;
}

bool NetAddr::operator==(const NetAddr& other) const {
    return std::memcmp(ip, other.ip, 16) == 0 && port == other.port;
}

bool NetAddr::operator<(const NetAddr& other) const {
    int cmp = std::memcmp(ip, other.ip, 16);
    if (cmp != 0) return cmp < 0;
    return port < other.port;
}

// ============================================================================
// VersionMessage
// ============================================================================

std::vector<uint8_t> VersionMessage::serialize() const {
    std::vector<uint8_t> out;

    writeU32(out, version);
    writeU64(out, services);
    writeU64(out, timestamp);

    auto recv = addr_recv.serialize(false);
    out.insert(out.end(), recv.begin(), recv.end());

    auto from = addr_from.serialize(false);
    out.insert(out.end(), from.begin(), from.end());

    writeU64(out, nonce);
    writeString(out, user_agent);
    writeU64(out, start_height);
    out.insert(out.end(), best_hash.begin(), best_hash.end());
    out.push_back(relay ? 1 : 0);
    out.insert(out.end(), node_id, node_id + 20);  // Node ID for deduplication

    return out;
}

std::optional<VersionMessage> VersionMessage::deserialize(const uint8_t* data, size_t len) {
    if (len < 86) return std::nullopt;  // Minimum size

    VersionMessage msg;
    size_t offset = 0;

    msg.version = readU32(data + offset); offset += 4;
    msg.services = readU64(data + offset); offset += 8;
    msg.timestamp = readU64(data + offset); offset += 8;

    auto recv = NetAddr::deserialize(data, len, offset, false);
    if (!recv) return std::nullopt;
    msg.addr_recv = *recv;

    auto from = NetAddr::deserialize(data, len, offset, false);
    if (!from) return std::nullopt;
    msg.addr_from = *from;

    if (offset + 8 > len) return std::nullopt;
    msg.nonce = readU64(data + offset); offset += 8;

    auto ua = readString(data, len, offset);
    if (!ua) return std::nullopt;
    msg.user_agent = *ua;

    if (offset + 8 > len) return std::nullopt;
    msg.start_height = readU64(data + offset); offset += 8;

    if (offset + 32 > len) return std::nullopt;
    std::memcpy(msg.best_hash.data(), data + offset, 32); offset += 32;

    if (offset < len) {
        msg.relay = data[offset] != 0;
        offset += 1;
    }

    // Read node_id if present (20 bytes)
    if (offset + 20 <= len) {
        std::memcpy(msg.node_id, data + offset, 20);
    }

    return msg;
}

// ============================================================================
// PingPongMessage
// ============================================================================

std::vector<uint8_t> PingPongMessage::serialize() const {
    std::vector<uint8_t> out;
    writeU64(out, nonce);
    return out;
}

std::optional<PingPongMessage> PingPongMessage::deserialize(const uint8_t* data, size_t len) {
    if (len < 8) return std::nullopt;
    PingPongMessage msg;
    msg.nonce = readU64(data);
    return msg;
}

// ============================================================================
// RejectMessage
// ============================================================================

std::vector<uint8_t> RejectMessage::serialize() const {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(message));
    out.push_back(code);
    writeString(out, reason);
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

std::optional<RejectMessage> RejectMessage::deserialize(const uint8_t* data, size_t len) {
    if (len < 2) return std::nullopt;

    RejectMessage msg;
    size_t offset = 0;

    msg.message = static_cast<MessageType>(data[offset++]);
    msg.code = data[offset++];

    auto reason = readString(data, len, offset);
    if (!reason) return std::nullopt;
    msg.reason = *reason;

    if (offset + 32 <= len) {
        std::memcpy(msg.data.data(), data + offset, 32);
    }

    return msg;
}

// ============================================================================
// InvMessage
// ============================================================================

std::vector<uint8_t> InvMessage::serialize() const {
    std::vector<uint8_t> out;
    writeVarint(out, items.size());
    for (const auto& item : items) {
        auto s = item.serialize();
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

std::optional<InvMessage> InvMessage::deserialize(const uint8_t* data, size_t len) {
    size_t offset = 0;
    auto count = chain::varint::decode(data, len, offset);
    if (!count || *count > MAX_INV_SIZE) return std::nullopt;

    InvMessage msg;
    msg.items.reserve(*count);

    for (uint64_t i = 0; i < *count; i++) {
        auto item = InvItem::deserialize(data, len, offset);
        if (!item) return std::nullopt;
        msg.items.push_back(*item);
    }

    return msg;
}

// ============================================================================
// GetBlocksMessage / GetHeadersMessage
// ============================================================================

std::vector<uint8_t> GetBlocksMessage::serialize() const {
    std::vector<uint8_t> out;
    writeU32(out, version);
    writeVarint(out, locator.size());
    for (const auto& hash : locator) {
        out.insert(out.end(), hash.begin(), hash.end());
    }
    out.insert(out.end(), hash_stop.begin(), hash_stop.end());
    return out;
}

std::optional<GetBlocksMessage> GetBlocksMessage::deserialize(const uint8_t* data, size_t len) {
    if (len < 4) return std::nullopt;

    GetBlocksMessage msg;
    size_t offset = 0;

    msg.version = readU32(data + offset); offset += 4;

    auto count = chain::varint::decode(data, len, offset);
    if (!count || *count > MAX_LOCATOR_SIZE) return std::nullopt;

    msg.locator.reserve(*count);
    for (uint64_t i = 0; i < *count; i++) {
        if (offset + 32 > len) return std::nullopt;
        crypto::Hash256 hash;
        std::memcpy(hash.data(), data + offset, 32);
        offset += 32;
        msg.locator.push_back(hash);
    }

    if (offset + 32 > len) return std::nullopt;
    std::memcpy(msg.hash_stop.data(), data + offset, 32);

    return msg;
}

std::vector<uint8_t> GetHeadersMessage::serialize() const {
    std::vector<uint8_t> out;
    writeU32(out, version);
    writeVarint(out, locator.size());
    for (const auto& hash : locator) {
        out.insert(out.end(), hash.begin(), hash.end());
    }
    out.insert(out.end(), hash_stop.begin(), hash_stop.end());
    return out;
}

std::optional<GetHeadersMessage> GetHeadersMessage::deserialize(const uint8_t* data, size_t len) {
    if (len < 4) return std::nullopt;

    GetHeadersMessage msg;
    size_t offset = 0;

    msg.version = readU32(data + offset); offset += 4;

    auto count = chain::varint::decode(data, len, offset);
    if (!count || *count > MAX_LOCATOR_SIZE) return std::nullopt;

    msg.locator.reserve(*count);
    for (uint64_t i = 0; i < *count; i++) {
        if (offset + 32 > len) return std::nullopt;
        crypto::Hash256 hash;
        std::memcpy(hash.data(), data + offset, 32);
        offset += 32;
        msg.locator.push_back(hash);
    }

    if (offset + 32 > len) return std::nullopt;
    std::memcpy(msg.hash_stop.data(), data + offset, 32);

    return msg;
}

// ============================================================================
// HeadersMessage
// ============================================================================

std::vector<uint8_t> HeadersMessage::serialize() const {
    std::vector<uint8_t> out;
    writeVarint(out, headers.size());
    for (const auto& hdr : headers) {
        auto s = hdr.serialize();
        out.insert(out.end(), s.begin(), s.end());
        out.push_back(0);  // tx_count (always 0 for headers)
    }
    return out;
}

std::optional<HeadersMessage> HeadersMessage::deserialize(const uint8_t* data, size_t len) {
    size_t offset = 0;
    auto count = chain::varint::decode(data, len, offset);
    if (!count || *count > MAX_HEADERS_SIZE) return std::nullopt;

    HeadersMessage msg;
    msg.headers.reserve(*count);

    for (uint64_t i = 0; i < *count; i++) {
        if (offset + 81 > len) return std::nullopt;  // 80 bytes header + 1 byte tx_count

        auto hdr = chain::BlockHeader::deserialize(data + offset, 80);
        if (!hdr) return std::nullopt;
        offset += 80;

        // Skip tx_count (should be 0)
        auto tx_count = chain::varint::decode(data, len, offset);
        if (!tx_count) return std::nullopt;

        msg.headers.push_back(*hdr);
    }

    return msg;
}

// ============================================================================
// BlockMessage
// ============================================================================

std::vector<uint8_t> BlockMessage::serialize() const {
    return block.serialize();
}

std::optional<BlockMessage> BlockMessage::deserialize(const uint8_t* data, size_t len) {
    auto blk = chain::Block::deserialize(data, len);
    if (!blk) return std::nullopt;

    BlockMessage msg;
    msg.block = *blk;
    return msg;
}

// ============================================================================
// TxMessage
// ============================================================================

std::vector<uint8_t> TxMessage::serialize() const {
    return tx.serialize();
}

std::optional<TxMessage> TxMessage::deserialize(const uint8_t* data, size_t len) {
    auto t = chain::Transaction::deserialize(data, len);
    if (!t) return std::nullopt;

    TxMessage msg;
    msg.tx = *t;
    return msg;
}

// ============================================================================
// AddrMessage
// ============================================================================

std::vector<uint8_t> AddrMessage::serialize() const {
    std::vector<uint8_t> out;
    writeVarint(out, addrs.size());
    for (const auto& addr : addrs) {
        auto s = addr.serialize(true);
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

std::optional<AddrMessage> AddrMessage::deserialize(const uint8_t* data, size_t len) {
    size_t offset = 0;
    auto count = chain::varint::decode(data, len, offset);
    if (!count || *count > MAX_ADDR_SIZE) return std::nullopt;

    AddrMessage msg;
    msg.addrs.reserve(*count);

    for (uint64_t i = 0; i < *count; i++) {
        auto addr = NetAddr::deserialize(data, len, offset, true);
        if (!addr) return std::nullopt;
        msg.addrs.push_back(*addr);
    }

    return msg;
}

// ============================================================================
// Message
// ============================================================================

std::vector<uint8_t> Message::serialize(uint32_t magic) const {
    // Serialize payload
    std::vector<uint8_t> payload_data = std::visit([](auto&& arg) {
        return arg.serialize();
    }, payload);

    // Calculate checksum
    auto checksum = calculateChecksum(payload_data.data(), payload_data.size());

    // Build header
    MessageHeader hdr = MessageHeader::create(magic, type, static_cast<uint32_t>(payload_data.size()), checksum.data());

    // Combine header + payload
    std::vector<uint8_t> out;
    out.reserve(MessageHeader::SIZE + payload_data.size());

    // Write header
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&hdr),
               reinterpret_cast<uint8_t*>(&hdr) + MessageHeader::SIZE);

    // Write payload
    out.insert(out.end(), payload_data.begin(), payload_data.end());

    return out;
}

bool Message::deserializePayload(const uint8_t* data, size_t len) {
    switch (type) {
        case MessageType::VERSION: {
            auto p = VersionMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::VERACK: {
            auto p = VerackMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::PING:
        case MessageType::PONG: {
            auto p = PingPongMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::REJECT: {
            auto p = RejectMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::INV:
        case MessageType::GETDATA:
        case MessageType::NOTFOUND: {
            auto p = InvMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::GETBLOCKS: {
            auto p = GetBlocksMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::GETHEADERS: {
            auto p = GetHeadersMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::HEADERS: {
            auto p = HeadersMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::BLOCK: {
            auto p = BlockMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::TX: {
            auto p = TxMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::MEMPOOL: {
            auto p = MempoolMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::GETADDR: {
            auto p = GetAddrMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        case MessageType::ADDR: {
            auto p = AddrMessage::deserialize(data, len);
            if (!p) return false;
            payload = *p;
            return true;
        }
        default:
            return false;
    }
}

std::optional<std::pair<Message, size_t>> Message::parse(
    const uint8_t* data, size_t len, uint32_t expected_magic) {

    if (len < MessageHeader::SIZE) return std::nullopt;

    // Parse header
    MessageHeader hdr;
    std::memcpy(&hdr, data, MessageHeader::SIZE);

    if (!hdr.isValid(expected_magic)) return std::nullopt;

    // Check if we have full payload
    size_t total_size = MessageHeader::SIZE + hdr.payload_size;
    if (len < total_size) return std::nullopt;

    // Verify checksum
    const uint8_t* payload = data + MessageHeader::SIZE;
    auto expected_checksum = calculateChecksum(payload, hdr.payload_size);
    if (std::memcmp(hdr.checksum, expected_checksum.data(), 4) != 0) {
        return std::nullopt;  // Invalid checksum
    }

    // Parse payload based on type
    Message msg;
    msg.type = static_cast<MessageType>(hdr.type);

    switch (msg.type) {
        case MessageType::VERSION: {
            auto p = VersionMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::VERACK: {
            auto p = VerackMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::PING:
        case MessageType::PONG: {
            auto p = PingPongMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::REJECT: {
            auto p = RejectMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::INV:
        case MessageType::GETDATA:
        case MessageType::NOTFOUND: {
            auto p = InvMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::GETBLOCKS: {
            auto p = GetBlocksMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::GETHEADERS: {
            auto p = GetHeadersMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::HEADERS: {
            auto p = HeadersMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::BLOCK: {
            auto p = BlockMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::TX: {
            auto p = TxMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::MEMPOOL: {
            auto p = MempoolMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::GETADDR: {
            auto p = GetAddrMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        case MessageType::ADDR: {
            auto p = AddrMessage::deserialize(payload, hdr.payload_size);
            if (!p) return std::nullopt;
            msg.payload = *p;
            break;
        }
        default:
            return std::nullopt;  // Unknown message type
    }

    return std::make_pair(msg, total_size);
}

// ============================================================================
// Block Locator
// ============================================================================

std::vector<crypto::Hash256> buildBlockLocator(
    uint64_t height,
    const std::function<crypto::Hash256(uint64_t)>& getHashAtHeight) {

    std::vector<crypto::Hash256> locator;

    int64_t step = 1;
    int64_t h = static_cast<int64_t>(height);

    while (h >= 0) {
        locator.push_back(getHashAtHeight(static_cast<uint64_t>(h)));

        if (h == 0) break;

        // Exponential back-off after first 10
        if (locator.size() >= 10) {
            step *= 2;
        }

        h -= step;
        if (h < 0) h = 0;
    }

    return locator;
}

} // namespace p2p
} // namespace ftc
