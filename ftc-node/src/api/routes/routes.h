#ifndef FTC_API_ROUTES_H
#define FTC_API_ROUTES_H

/**
 * FTC Node API Routes
 * Kristian Pilatovich 20091227 - First Real P2P
 *
 * Route modules for the REST API server.
 * Each module registers its endpoints with the server.
 */

#include "api/server.h"
#include "chain/chain.h"
#include "chain/mempool.h"
#include "chain/utxo_set.h"
#include "p2p/peer_manager.h"
#include "p2pool/p2pool_net.h"
#include "crypto/keccak256.h"
#include "crypto/secp256k1.h"
#include "crypto/bech32.h"

namespace ftc {
namespace api {
namespace routes {

//-----------------------------------------------------------------------------
// Helper functions (shared across route modules)
//-----------------------------------------------------------------------------

// Convert Hash256 to hex string
inline std::string hashToHex(const crypto::Hash256& hash) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto& byte : hash) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

// Convert hex string to Hash256
inline bool hexToHash(const std::string& hex, crypto::Hash256& hash) {
    if (hex.size() != 64) return false;
    auto hexCharToNibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 32; ++i) {
        int hi = hexCharToNibble(hex[i * 2]);
        int lo = hexCharToNibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        hash[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// Convert bytes to hex string
inline std::string bytesToHex(const std::vector<uint8_t>& data) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

//-----------------------------------------------------------------------------
// Route context - dependencies for route handlers
//-----------------------------------------------------------------------------

struct RouteContext {
    Server* server;
    chain::Chain* chain;
    chain::Mempool* mempool;
    chain::UTXOSet* utxo_set;
    p2p::PeerManager* peer_manager;
    p2pool::P2Pool* p2pool;
};

//-----------------------------------------------------------------------------
// Route registration functions
//-----------------------------------------------------------------------------

// Status routes: /, /status, /health, /genesis
void setupStatusRoutes(RouteContext& ctx);

// Chain routes: /block, /tx, /mempool
void setupChainRoutes(RouteContext& ctx);

// Address routes: /balance, /utxo, /address/:addr/history
void setupAddressRoutes(RouteContext& ctx);

// Wallet routes: /wallet/new, /wallet/send
void setupWalletRoutes(RouteContext& ctx);

// Mining routes: /mining/*
void setupMiningRoutes(RouteContext& ctx);

// P2Pool routes: /p2pool/*
void setupP2PoolRoutes(RouteContext& ctx);

} // namespace routes
} // namespace api
} // namespace ftc

#endif // FTC_API_ROUTES_H
