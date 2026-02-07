// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/network.h"
#include "rpc/util.h"

#include "core/logging.h"
#include "core/time.h"
#include "net/manager/conn_manager.h"
#include "net/manager/net_manager.h"
#include "net/peer/peer_state.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace rpc {

// ===========================================================================
// getpeerinfo
// ===========================================================================

RpcResponse rpc_getpeerinfo(const RpcRequest& req,
                             net::NetManager& netmgr) {
    auto& conn_mgr = netmgr.conn_manager();
    auto peer_ids = conn_mgr.get_peer_ids();

    JsonValue::Array peers;
    for (uint64_t id : peer_ids) {
        const auto* peer = conn_mgr.get_peer(id);
        if (!peer) continue;

        JsonValue obj(JsonValue::Object{});
        obj["id"]             = JsonValue(static_cast<int64_t>(peer->id));
        obj["addr"]           = JsonValue(peer->conn.remote_address());
        obj["services"]       = JsonValue(hex_encode(
            reinterpret_cast<const uint8_t*>(&peer->services), 8));
        obj["relaytxes"]      = JsonValue(peer->relay);
        obj["lastsend"]       = JsonValue(peer->stats.last_send);
        obj["lastrecv"]       = JsonValue(peer->stats.last_recv);
        obj["bytessent"]      = JsonValue(
            static_cast<int64_t>(peer->stats.bytes_sent));
        obj["bytesrecv"]      = JsonValue(
            static_cast<int64_t>(peer->stats.bytes_recv));
        obj["conntime"]       = JsonValue(peer->stats.connected_time);
        obj["timeoffset"]     = JsonValue(static_cast<int64_t>(0));
        obj["pingtime"]       = JsonValue(
            peer->stats.ping_time >= 0
                ? static_cast<double>(peer->stats.ping_time) / 1000.0
                : -1.0);
        obj["version"]        = JsonValue(static_cast<int64_t>(peer->version));
        obj["subver"]         = JsonValue(peer->user_agent);
        obj["inbound"]        = JsonValue(peer->inbound);
        obj["startingheight"] = JsonValue(
            static_cast<int64_t>(peer->start_height));
        obj["banscore"]       = JsonValue(
            static_cast<int64_t>(peer->stats.misbehavior_score));
        obj["synced_headers"] = JsonValue(static_cast<int64_t>(-1));
        obj["synced_blocks"]  = JsonValue(static_cast<int64_t>(-1));

        // Connection state
        obj["connection_type"] = JsonValue(
            peer->inbound ? "inbound" : "outbound-full-relay");

        peers.push_back(std::move(obj));
    }

    return make_result(JsonValue(std::move(peers)), req.id);
}

// ===========================================================================
// getconnectioncount
// ===========================================================================

RpcResponse rpc_getconnectioncount(const RpcRequest& req,
                                    net::NetManager& netmgr) {
    return make_result(
        JsonValue(static_cast<int64_t>(netmgr.peer_count())),
        req.id);
}

// ===========================================================================
// getnettotals
// ===========================================================================

RpcResponse rpc_getnettotals(const RpcRequest& req,
                              net::NetManager& netmgr) {
    auto& conn_mgr = netmgr.conn_manager();
    auto peer_ids = conn_mgr.get_peer_ids();

    uint64_t total_sent = 0;
    uint64_t total_recv = 0;

    for (uint64_t id : peer_ids) {
        const auto* peer = conn_mgr.get_peer(id);
        if (!peer) continue;
        total_sent += peer->stats.bytes_sent;
        total_recv += peer->stats.bytes_recv;
    }

    JsonValue result(JsonValue::Object{});
    result["totalbytesrecv"] = JsonValue(static_cast<int64_t>(total_recv));
    result["totalbytessent"] = JsonValue(static_cast<int64_t>(total_sent));
    result["timemillis"]     = JsonValue(core::get_time_millis());

    // Upload/download target (unlimited)
    JsonValue target(JsonValue::Object{});
    target["timeframe"]     = JsonValue(static_cast<int64_t>(86400));
    target["target"]        = JsonValue(static_cast<int64_t>(0));
    target["target_reached"] = JsonValue(false);
    target["serve_historical_blocks"] = JsonValue(true);
    target["bytes_left_in_cycle"]     = JsonValue(static_cast<int64_t>(0));
    target["time_left_in_cycle"]      = JsonValue(static_cast<int64_t>(0));
    result["uploadtarget"] = std::move(target);

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// addnode
// ===========================================================================

RpcResponse rpc_addnode(const RpcRequest& req,
                         net::NetManager& netmgr) {
    std::string node_addr = param_string(req.params, 0);
    std::string command   = param_string(req.params, 1);

    if (command != "add" && command != "remove" && command != "onetry") {
        return make_error(RpcError::INVALID_PARAMS,
                          "Invalid command: must be 'add', 'remove', or 'onetry'",
                          req.id);
    }

    // Parse host:port
    std::string host = node_addr;
    uint16_t port = 9333; // default FTC P2P port

    auto colon_pos = node_addr.rfind(':');
    if (colon_pos != std::string::npos) {
        host = node_addr.substr(0, colon_pos);
        std::string port_str = node_addr.substr(colon_pos + 1);
        try {
            int p = std::stoi(port_str);
            if (p > 0 && p <= 65535) {
                port = static_cast<uint16_t>(p);
            }
        } catch (...) {
            // use default port
        }
    }

    if (command == "onetry" || command == "add") {
        auto result = netmgr.connect_to(host, port);
        if (!result.ok()) {
            return make_error(RpcError::MISC_ERROR,
                              "Failed to connect: " + result.error().message(),
                              req.id);
        }
        LOG_INFO(core::LogCategory::RPC,
                 "addnode: connected to " + node_addr);
    } else if (command == "remove") {
        // Find and disconnect the peer by address
        auto& conn_mgr = netmgr.conn_manager();
        auto peer_ids = conn_mgr.get_peer_ids();
        bool found = false;
        for (uint64_t id : peer_ids) {
            const auto* peer = conn_mgr.get_peer(id);
            if (peer && peer->conn.remote_address() == node_addr) {
                netmgr.disconnect(id);
                found = true;
                break;
            }
        }
        if (!found) {
            return make_error(RpcError::MISC_ERROR,
                              "Node not found: " + node_addr, req.id);
        }
    }

    return make_result(JsonValue(nullptr), req.id);
}

// ===========================================================================
// disconnectnode
// ===========================================================================

RpcResponse rpc_disconnectnode(const RpcRequest& req,
                                net::NetManager& netmgr) {
    // Can disconnect by address (string) or by peer ID (integer)
    const auto& p = req.params;

    if (param_exists(p, 0) && param_value(p, 0).is_int()) {
        uint64_t peer_id = static_cast<uint64_t>(param_int(p, 0));
        netmgr.disconnect(peer_id);
        return make_result(JsonValue(nullptr), req.id);
    }

    if (param_exists(p, 0) && param_value(p, 0).is_string()) {
        std::string addr = param_string(p, 0);
        auto& conn_mgr = netmgr.conn_manager();
        auto peer_ids = conn_mgr.get_peer_ids();
        for (uint64_t id : peer_ids) {
            const auto* peer = conn_mgr.get_peer(id);
            if (peer && peer->conn.remote_address() == addr) {
                netmgr.disconnect(id);
                return make_result(JsonValue(nullptr), req.id);
            }
        }
        return make_error(RpcError::MISC_ERROR,
                          "Node not found: " + addr, req.id);
    }

    // Check named parameter "nodeid"
    if (p.is_object() && p.has_key("nodeid")) {
        uint64_t peer_id = static_cast<uint64_t>(p["nodeid"].get_int());
        netmgr.disconnect(peer_id);
        return make_result(JsonValue(nullptr), req.id);
    }

    return make_error(RpcError::INVALID_PARAMS,
                      "Expected address or node id", req.id);
}

// ===========================================================================
// getnetworkinfo
// ===========================================================================

RpcResponse rpc_getnetworkinfo(const RpcRequest& req,
                                net::NetManager& netmgr) {
    JsonValue result(JsonValue::Object{});
    result["version"]         = JsonValue(static_cast<int64_t>(1000000)); // v1.0.0
    result["subversion"]      = JsonValue("/FTC:1.0.0/");
    result["protocolversion"] = JsonValue(static_cast<int64_t>(70016));
    result["localservices"]   = JsonValue("0000000000000009");
    result["localrelay"]      = JsonValue(true);
    result["timeoffset"]      = JsonValue(static_cast<int64_t>(0));
    result["networkactive"]   = JsonValue(netmgr.is_running());
    result["connections"]     = JsonValue(
        static_cast<int64_t>(netmgr.peer_count()));
    result["connections_in"]  = JsonValue(
        static_cast<int64_t>(netmgr.conn_manager().inbound_count()));
    result["connections_out"] = JsonValue(
        static_cast<int64_t>(netmgr.outbound_count()));

    // Networks
    JsonValue::Array networks;
    {
        JsonValue ipv4(JsonValue::Object{});
        ipv4["name"]       = JsonValue("ipv4");
        ipv4["limited"]    = JsonValue(false);
        ipv4["reachable"]  = JsonValue(true);
        ipv4["proxy"]      = JsonValue("");
        ipv4["proxy_randomize_credentials"] = JsonValue(false);
        networks.push_back(std::move(ipv4));
    }
    {
        JsonValue ipv6(JsonValue::Object{});
        ipv6["name"]       = JsonValue("ipv6");
        ipv6["limited"]    = JsonValue(false);
        ipv6["reachable"]  = JsonValue(true);
        ipv6["proxy"]      = JsonValue("");
        ipv6["proxy_randomize_credentials"] = JsonValue(false);
        networks.push_back(std::move(ipv6));
    }
    result["networks"] = JsonValue(std::move(networks));

    // Relay fee
    result["relayfee"]      = JsonValue(0.00001);
    result["incrementalfee"] = JsonValue(0.00001);

    // Local addresses (empty for privacy by default)
    result["localaddresses"] = JsonValue(JsonValue::Array{});

    // Warnings
    result["warnings"] = JsonValue("");

    return make_result(std::move(result), req.id);
}

// ===========================================================================
// Registration
// ===========================================================================

void register_network_rpcs(RpcServer& server, net::NetManager& netmgr) {
    server.register_commands({
        {"getpeerinfo",
         [&](const RpcRequest& r) { return rpc_getpeerinfo(r, netmgr); },
         "getpeerinfo\n"
         "Returns data about each connected network node.",
         "network"},

        {"getconnectioncount",
         [&](const RpcRequest& r) { return rpc_getconnectioncount(r, netmgr); },
         "getconnectioncount\n"
         "Returns the number of connections to other nodes.",
         "network"},

        {"getnettotals",
         [&](const RpcRequest& r) { return rpc_getnettotals(r, netmgr); },
         "getnettotals\n"
         "Returns information about network traffic.",
         "network"},

        {"addnode",
         [&](const RpcRequest& r) { return rpc_addnode(r, netmgr); },
         "addnode \"node\" \"command\"\n"
         "Attempts to add or remove a node from the addnode list.\n"
         "command: 'add', 'remove', or 'onetry'.",
         "network"},

        {"disconnectnode",
         [&](const RpcRequest& r) { return rpc_disconnectnode(r, netmgr); },
         "disconnectnode ( \"address\" nodeid )\n"
         "Immediately disconnects from the specified peer node.\n"
         "Provide address or nodeid.",
         "network"},

        {"getnetworkinfo",
         [&](const RpcRequest& r) { return rpc_getnetworkinfo(r, netmgr); },
         "getnetworkinfo\n"
         "Returns an object containing various state info regarding P2P networking.",
         "network"},
    });
}

} // namespace rpc
