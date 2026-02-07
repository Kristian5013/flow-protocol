// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Genesis block miner for the FTC cryptocurrency.
// Embeds "Pilatovich Kristian 20091227" in the coinbase scriptSig,
// sets the timestamp to 2026-02-03 00:00:00 UTC, and mines with
// keccak256d proof-of-work until a hash meeting the target is found.

#include "consensus/params.h"
#include "core/hex.h"
#include "core/stream.h"
#include "core/types.h"
#include "crypto/keccak.h"
#include "miner/difficulty.h"
#include "miner/solver.h"
#include "primitives/block.h"
#include "primitives/block_header.h"
#include "primitives/transaction.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "  FTC Genesis Block Miner" << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << std::endl;

    const auto& params = consensus::ConsensusParams::mainnet_params();

    // ---- Build the coinbase transaction from consensus params ----
    auto coinbase_tx = params.create_genesis_coinbase();
    auto txid = coinbase_tx.txid();

    std::cout << "Genesis message: " << params.genesis_message << std::endl;
    std::cout << "Coinbase TXID:   " << txid.to_hex() << std::endl;
    std::cout << std::endl;

    // ---- Compute merkle root (just the coinbase) ----
    // For a single transaction, the merkle root = the txid
    core::uint256 merkle_root = txid;

    std::cout << "Merkle root:     " << merkle_root.to_hex() << std::endl;

    // ---- Build the genesis block header from params ----
    primitives::BlockHeader header = params.genesis_block;
    header.merkle_root = merkle_root;

    // ---- Compute the difficulty target ----
    core::uint256 target = miner::bits_to_target(header.bits);

    std::cout << "Timestamp:       1738540800 (2026-02-03 00:00:00 UTC)" << std::endl;
    std::cout << "Bits:            0x" << std::hex << header.bits << std::dec << std::endl;
    std::cout << "Target:          " << target.to_hex() << std::endl;
    std::cout << std::endl;

    // ---- Print coinbase scriptSig hex ----
    const auto& scriptsig = coinbase_tx.vin()[0].script_sig;
    std::cout << "Coinbase scriptSig: "
              << core::to_hex(std::span<const uint8_t>(scriptsig.data(), scriptsig.size()))
              << std::endl;
    std::cout << std::endl;

    // ---- Mine ----
    std::cout << "Mining genesis block (keccak256d PoW)..." << std::endl;
    std::cout << std::endl;

    auto start_time = std::chrono::steady_clock::now();

    miner::EquihashSolver solver;
    std::atomic<bool> cancel{false};

    auto result = solver.solve(header, target, cancel);

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();

    if (!result.has_value()) {
        std::cerr << "ERROR: Failed to mine genesis block!" << std::endl;
        std::cerr << "Exhausted nonce space without finding a valid solution."
                  << std::endl;
        return 1;
    }

    // ---- Success! ----
    uint32_t winning_nonce = result->nonce;

    // Compute the final block hash using header.hash() = keccak256d(80-byte header).
    header.nonce = winning_nonce;
    core::uint256 block_hash = header.hash();

    std::cout << "==========================================" << std::endl;
    std::cout << "  GENESIS BLOCK MINED!" << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Time elapsed:    " << elapsed_ms << " ms" << std::endl;
    std::cout << "Nonce:           " << winning_nonce << std::endl;
    std::cout << "Block hash:      " << block_hash.to_hex() << std::endl;
    std::cout << "Merkle root:     " << merkle_root.to_hex() << std::endl;
    std::cout << std::endl;

    // ---- Verify ----
    bool valid = block_hash <= target && !target.is_zero();
    std::cout << "PoW valid:       " << (valid ? "YES" : "NO") << std::endl;
    std::cout << std::endl;

    // ---- Output code to paste into params.cpp ----
    std::cout << "==========================================" << std::endl;
    std::cout << "  Code for consensus/params.cpp:" << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "p.genesis_block.version     = 1;" << std::endl;
    std::cout << "p.genesis_block.prev_hash   = core::uint256{};" << std::endl;
    std::cout << "p.genesis_block.merkle_root = core::uint256::from_hex(\""
              << merkle_root.to_hex() << "\");" << std::endl;
    std::cout << "p.genesis_block.timestamp   = 1738540800;" << std::endl;
    std::cout << "p.genesis_block.bits        = 0x" << std::hex << header.bits
              << std::dec << ";" << std::endl;
    std::cout << "p.genesis_block.nonce       = " << winning_nonce << ";" << std::endl;
    std::cout << std::endl;
    std::cout << "// Genesis block hash: " << block_hash.to_hex() << std::endl;
    std::cout << std::endl;

    // ---- Full block serialization ----
    auto block_bytes = primitives::Block(header, {coinbase_tx}).serialize();
    std::cout << "// Full genesis block (" << block_bytes.size() << " bytes):" << std::endl;
    std::cout << "// "
              << core::to_hex(std::span<const uint8_t>(block_bytes.data(),
                                                        std::min(block_bytes.size(), size_t(160))))
              << "..." << std::endl;

    return 0;
}
