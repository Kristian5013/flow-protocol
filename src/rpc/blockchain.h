#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_BLOCKCHAIN_H
#define FTC_RPC_BLOCKCHAIN_H

#include "rpc/request.h"
#include "rpc/server.h"

#include <vector>

// Forward declarations
namespace chain {
    class ChainstateManager;
} // namespace chain

namespace rpc {

// ---------------------------------------------------------------------------
// Blockchain RPC command handlers
// ---------------------------------------------------------------------------

/// getblockchaininfo: chain height, best block hash, difficulty, etc.
RpcResponse rpc_getblockchaininfo(const RpcRequest& req,
                                   chain::ChainstateManager& chainstate);

/// getblock(hash, verbosity): return block data
///   verbosity 0 = hex serialization
///   verbosity 1 = json object
///   verbosity 2 = json object with full transaction details
RpcResponse rpc_getblock(const RpcRequest& req,
                          chain::ChainstateManager& chainstate);

/// getblockhash(height): return hash of block at given height
RpcResponse rpc_getblockhash(const RpcRequest& req,
                              chain::ChainstateManager& chainstate);

/// getblockheader(hash, verbose): return block header data
RpcResponse rpc_getblockheader(const RpcRequest& req,
                                chain::ChainstateManager& chainstate);

/// getblockcount: return the height of the most-work fully-validated chain
RpcResponse rpc_getblockcount(const RpcRequest& req,
                               chain::ChainstateManager& chainstate);

/// getdifficulty: return the proof-of-work difficulty as a multiple
RpcResponse rpc_getdifficulty(const RpcRequest& req,
                               chain::ChainstateManager& chainstate);

/// getchaintips: return info about all known chain tips
RpcResponse rpc_getchaintips(const RpcRequest& req,
                              chain::ChainstateManager& chainstate);

/// getbestblockhash: return the hash of the best (tip) block
RpcResponse rpc_getbestblockhash(const RpcRequest& req,
                                  chain::ChainstateManager& chainstate);

/// gettxout(txid, n): query a specific UTXO from the UTXO cache
RpcResponse rpc_gettxout(const RpcRequest& req,
                           chain::ChainstateManager& chainstate);

/// scantxoutset("start", [{"address":"..."}]): scan UTXO set for outputs
/// matching the given addresses.
RpcResponse rpc_scantxoutset(const RpcRequest& req,
                               chain::ChainstateManager& chainstate);

// ---------------------------------------------------------------------------
// Registration helper
// ---------------------------------------------------------------------------

/// Register all blockchain RPC commands with the server.
/// The chainstate reference is captured by the command closures.
void register_blockchain_rpcs(RpcServer& server,
                               chain::ChainstateManager& chainstate);

} // namespace rpc

#endif // FTC_RPC_BLOCKCHAIN_H
