// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "net/address/netaddress.h"
#include "net/address/subnet.h"
#include "net/transport/message.h"
#include "net/protocol/inventory.h"

#include <string>
#include <vector>

// ===================================================================
// NetAddress tests
// ===================================================================

TEST_CASE(NetAddress, DefaultConstruction) {
    net::NetAddress addr;
    // Default-constructed address is IPv4 zero.
    CHECK(addr.is_ipv4());
    CHECK(!addr.is_ipv6());
    CHECK_EQ(addr.get_network(), net::Network::IPV4);
}

TEST_CASE(NetAddress, FromIPv4) {
    // 127.0.0.1 = 0x7F000001 in host order
    auto addr = net::NetAddress::from_ipv4(0x7F000001);
    CHECK(addr.is_ipv4());
    CHECK(!addr.is_ipv6());
    CHECK(addr.is_local());
    CHECK(addr.is_valid());
    CHECK_EQ(addr.get_network(), net::Network::IPV4);
    CHECK_EQ(addr.get_ipv4(), static_cast<uint32_t>(0x7F000001));
    CHECK_EQ(addr.to_string(), std::string("127.0.0.1"));
}

TEST_CASE(NetAddress, FromIPv6) {
    // ::1 (loopback) in 16 bytes
    uint8_t ipv6_bytes[16] = {};
    ipv6_bytes[15] = 1;
    std::span<const uint8_t, 16> span{ipv6_bytes, 16};
    auto addr = net::NetAddress::from_ipv6(span);
    CHECK(addr.is_ipv6());
    CHECK(!addr.is_ipv4());
    CHECK(addr.is_valid());
    CHECK_EQ(addr.get_network(), net::Network::IPV6);
}

TEST_CASE(NetAddress, EqualityAndComparison) {
    auto a = net::NetAddress::from_ipv4(0x0A000001); // 10.0.0.1
    auto b = net::NetAddress::from_ipv4(0x0A000001); // 10.0.0.1
    auto c = net::NetAddress::from_ipv4(0x0A000002); // 10.0.0.2

    CHECK(a == b);
    CHECK_NE(a, c);
    CHECK_NE(b, c);
}

TEST_CASE(NetAddress, FromStringIPv4) {
    auto result = net::NetAddress::from_string("192.168.1.1");
    CHECK_OK(result);
    auto addr = result.value();
    CHECK(addr.is_ipv4());
    CHECK_EQ(addr.to_string(), std::string("192.168.1.1"));
    CHECK(addr.is_rfc1918()); // 192.168.x.x is private
}

TEST_CASE(NetAddress, FromStringInvalid) {
    auto result = net::NetAddress::from_string("not_an_address");
    CHECK_ERR(result);
}

TEST_CASE(NetAddress, NetworkName) {
    auto name = net::network_name(net::Network::IPV4);
    CHECK(!name.empty());
    auto name6 = net::network_name(net::Network::IPV6);
    CHECK(!name6.empty());
    CHECK_NE(name, name6);
}

// ===================================================================
// AddressWithPort tests
// ===================================================================

TEST_CASE(AddressWithPort, Construction) {
    net::AddressWithPort awp;
    // Default port is 9333
    CHECK_EQ(awp.port, static_cast<uint16_t>(9333));
    CHECK_EQ(awp.timestamp, static_cast<int64_t>(0));
    CHECK_EQ(awp.services, static_cast<uint64_t>(0));
}

TEST_CASE(AddressWithPort, FromString) {
    auto result = net::AddressWithPort::from_string("10.0.0.1:8080");
    CHECK_OK(result);
    auto awp = result.value();
    CHECK_EQ(awp.port, static_cast<uint16_t>(8080));
    CHECK(awp.addr.is_ipv4());
}

TEST_CASE(AddressWithPort, FromStringDefaultPort) {
    auto result = net::AddressWithPort::from_string("10.0.0.1");
    CHECK_OK(result);
    auto awp = result.value();
    // Should use default port 9333
    CHECK_EQ(awp.port, static_cast<uint16_t>(9333));
}

TEST_CASE(AddressWithPort, EqualityAndServices) {
    net::AddressWithPort a;
    a.addr = net::NetAddress::from_ipv4(0x0A000001);
    a.port = 9333;
    a.services = net::NODE_NETWORK | net::NODE_WITNESS;

    net::AddressWithPort b;
    b.addr = net::NetAddress::from_ipv4(0x0A000001);
    b.port = 9333;
    b.services = net::NODE_NETWORK | net::NODE_WITNESS;

    CHECK(a == b);

    // Different port should differ
    net::AddressWithPort c = a;
    c.port = 8333;
    CHECK_NE(a, c);
}

TEST_CASE(AddressWithPort, ServicesToString) {
    auto desc = net::AddressWithPort::services_to_string(
        net::NODE_NETWORK | net::NODE_WITNESS);
    CHECK(!desc.empty());
}

// ===================================================================
// Subnet tests
// ===================================================================

TEST_CASE(Subnet, ConstructionAndContains) {
    // Build a /24 subnet: 10.0.0.0/24
    auto base = net::NetAddress::from_ipv4(0x0A000000); // 10.0.0.0
    net::Subnet subnet(base, 24);

    CHECK(subnet.is_valid());
    CHECK_EQ(subnet.prefix_bits(), static_cast<uint8_t>(24));

    // 10.0.0.1 should be inside
    auto inside = net::NetAddress::from_ipv4(0x0A000001);
    CHECK(subnet.contains(inside));

    // 10.0.1.0 should be outside
    auto outside = net::NetAddress::from_ipv4(0x0A000100);
    CHECK(!subnet.contains(outside));
}

TEST_CASE(Subnet, FromString) {
    auto result = net::Subnet::from_string("192.168.0.0/16");
    CHECK_OK(result);
    auto subnet = result.value();
    CHECK(subnet.is_valid());
    CHECK_EQ(subnet.prefix_bits(), static_cast<uint8_t>(16));

    auto addr = net::NetAddress::from_ipv4(0xC0A80101); // 192.168.1.1
    CHECK(subnet.contains(addr));

    auto out = net::NetAddress::from_ipv4(0x0A000001); // 10.0.0.1
    CHECK(!subnet.contains(out));
}

TEST_CASE(Subnet, SingleHost) {
    auto addr = net::NetAddress::from_ipv4(0x08080808); // 8.8.8.8
    auto subnet = net::Subnet::from_address(addr);
    CHECK(subnet.is_single_host());
    CHECK(subnet.contains(addr));

    auto other = net::NetAddress::from_ipv4(0x08080809); // 8.8.8.9
    CHECK(!subnet.contains(other));
}

TEST_CASE(Subnet, ContainsSubnet) {
    // /16 should contain /24
    auto big = net::Subnet(net::NetAddress::from_ipv4(0x0A000000), 16);   // 10.0.0.0/16
    auto small = net::Subnet(net::NetAddress::from_ipv4(0x0A000000), 24); // 10.0.0.0/24
    CHECK(big.contains_subnet(small));
    CHECK(!small.contains_subnet(big));
}

// ===================================================================
// Message tests
// ===================================================================

TEST_CASE(Message, HeaderConstants) {
    CHECK_EQ(net::MessageHeader::MAGIC, static_cast<uint32_t>(0x46544321));
    CHECK_EQ(net::MessageHeader::HEADER_SIZE, static_cast<size_t>(24));
    CHECK_EQ(net::MessageHeader::COMMAND_SIZE, static_cast<size_t>(12));
    CHECK_EQ(net::MessageHeader::MAX_PAYLOAD_SIZE, static_cast<size_t>(32 * 1024 * 1024));
}

TEST_CASE(Message, HeaderSetGetCommand) {
    net::MessageHeader hdr;
    hdr.set_command("version");
    CHECK_EQ(hdr.get_command(), std::string("version"));

    hdr.set_command("ping");
    CHECK_EQ(hdr.get_command(), std::string("ping"));
}

TEST_CASE(Message, CreateAndVerify) {
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    auto msg = net::Message::create("tx", payload);

    CHECK_EQ(msg.header.get_command(), std::string("tx"));
    CHECK_EQ(msg.header.magic, net::MessageHeader::MAGIC);
    CHECK_EQ(msg.header.payload_size, static_cast<uint32_t>(4));
    CHECK_EQ(msg.payload.size(), static_cast<size_t>(4));
    CHECK(msg.verify_checksum());
}

TEST_CASE(Message, EmptyPayload) {
    auto msg = net::Message::create("verack", {});
    CHECK_EQ(msg.header.get_command(), std::string("verack"));
    CHECK_EQ(msg.header.payload_size, static_cast<uint32_t>(0));
    CHECK_EQ(msg.payload.size(), static_cast<size_t>(0));
    CHECK(msg.verify_checksum());
}

TEST_CASE(Message, SerializeRoundTrip) {
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    auto msg = net::Message::create("block", payload);

    auto bytes = msg.header.serialize();
    CHECK_EQ(bytes.size(), static_cast<size_t>(net::MessageHeader::HEADER_SIZE));

    auto result = net::MessageHeader::deserialize(bytes);
    CHECK_OK(result);
    auto hdr2 = result.value();
    CHECK_EQ(hdr2.get_command(), std::string("block"));
    CHECK_EQ(hdr2.payload_size, static_cast<uint32_t>(4));
    CHECK_EQ(hdr2.magic, net::MessageHeader::MAGIC);
    CHECK_EQ(hdr2.checksum, msg.header.checksum);
}

// ===================================================================
// InvItem / InvType tests
// ===================================================================

TEST_CASE(InvItem, TypeQueries) {
    CHECK(!net::protocol::inv_is_witness(net::protocol::InvType::TX));
    CHECK(!net::protocol::inv_is_witness(net::protocol::InvType::BLOCK));
    CHECK(net::protocol::inv_is_witness(net::protocol::InvType::WITNESS_TX));
    CHECK(net::protocol::inv_is_witness(net::protocol::InvType::WITNESS_BLOCK));

    CHECK_EQ(net::protocol::inv_base_type(net::protocol::InvType::WITNESS_TX),
             net::protocol::InvType::TX);
    CHECK_EQ(net::protocol::inv_base_type(net::protocol::InvType::WITNESS_BLOCK),
             net::protocol::InvType::BLOCK);
    CHECK_EQ(net::protocol::inv_base_type(net::protocol::InvType::TX),
             net::protocol::InvType::TX);
}

TEST_CASE(InvItem, Construction) {
    net::protocol::InvItem item;
    item.type = net::protocol::InvType::TX;
    item.hash = core::uint256::from_hex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

    CHECK_EQ(item.type, net::protocol::InvType::TX);
    CHECK(!item.hash.is_zero());
}

TEST_CASE(InvItem, Equality) {
    auto hash = core::uint256::from_hex(
        "00000000000000000007878ec04bb2b2e12317804571f7d30763e4d0e4a5e01e");

    net::protocol::InvItem a;
    a.type = net::protocol::InvType::BLOCK;
    a.hash = hash;

    net::protocol::InvItem b;
    b.type = net::protocol::InvType::BLOCK;
    b.hash = hash;

    CHECK(a == b);

    net::protocol::InvItem c;
    c.type = net::protocol::InvType::TX;
    c.hash = hash;

    CHECK(a != c); // different type
}

TEST_CASE(InvItem, TypeName) {
    const char* tx_name = net::protocol::inv_type_name(net::protocol::InvType::TX);
    CHECK(tx_name != nullptr);

    const char* block_name = net::protocol::inv_type_name(net::protocol::InvType::BLOCK);
    CHECK(block_name != nullptr);
}

TEST_CASE(InvItem, ToString) {
    net::protocol::InvItem item;
    item.type = net::protocol::InvType::BLOCK;
    item.hash = core::uint256::from_hex(
        "0000000000000003fa89e1e22a83b1c07873e5c2e5a3f3e80e26b6c39e0837f4");

    auto str = item.to_string();
    CHECK(!str.empty());
}

TEST_CASE(InvItem, InvMessageValidateEmpty) {
    net::protocol::InvMessage inv_msg;
    // Empty inv message should be valid
    auto result = inv_msg.validate();
    CHECK_OK(result);
}

TEST_CASE(InvItem, CommandNames) {
    // Verify standard command name constants are accessible and non-empty
    CHECK(std::string(net::commands::VERSION) == "version");
    CHECK(std::string(net::commands::VERACK) == "verack");
    CHECK(std::string(net::commands::INV) == "inv");
    CHECK(std::string(net::commands::PING) == "ping");
    CHECK(std::string(net::commands::PONG) == "pong");
    CHECK(std::string(net::commands::TX) == "tx");
    CHECK(std::string(net::commands::BLOCK) == "block");
}
