#ifndef FTC_CHAIN_GENESIS_H
#define FTC_CHAIN_GENESIS_H

#include "chain/block.h"
#include "crypto/keccak256.h"

namespace ftc {
namespace chain {

/**
 * Genesis Block Parameters
 *
 * The genesis block is the first block in the blockchain.
 * It contains a special message and initializes the chain.
 */
namespace genesis {

// Genesis block timestamp: 2026-01-20 00:00:00 UTC
constexpr uint32_t GENESIS_TIME = 1737331200;

// Genesis block message (in coinbase)
constexpr const char* GENESIS_MESSAGE = "Kristian Pilatovich 20091227 - First Real P2P";

// Genesis block parameters
constexpr uint32_t GENESIS_VERSION = 1;
constexpr uint32_t GENESIS_BITS = 0x1c00ffff;  // Difficulty 256 (~10 min blocks at 1 GH/s)
constexpr uint32_t GENESIS_NONCE = 0;          // Will be mined

// Initial block reward: 50 FTC
constexpr uint64_t GENESIS_REWARD = 50 * 100000000ULL;

// NOTE: Genesis block is created by ftc::chain::createGenesisBlock() in block.cpp
// Do not create duplicate implementations here to avoid hash mismatches!

/**
 * Get the genesis block hash (for testnet)
 *
 * Note: This hash will change if genesis block parameters change.
 * The actual mainnet hash will be computed after mining.
 */
inline crypto::Hash256 getGenesisHash() {
    static crypto::Hash256 hash;
    static bool computed = false;

    if (!computed) {
        Block genesis = createGenesisBlock();
        hash = genesis.getHash();
        computed = true;
    }

    return hash;
}

} // namespace genesis
} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_GENESIS_H
