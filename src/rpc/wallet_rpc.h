#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FTC_RPC_WALLET_RPC_H
#define FTC_RPC_WALLET_RPC_H

#include "rpc/request.h"
#include "rpc/server.h"

// Forward declaration of wallet module types.
// The wallet module is optional; the RPC layer uses a nullable pointer.
namespace wallet {
    class Wallet;
} // namespace wallet

namespace rpc {

/// getbalance: return the wallet balance.
RpcResponse rpc_getbalance(const RpcRequest& req, wallet::Wallet* wallet);

/// getnewaddress: generate a new receiving address.
RpcResponse rpc_getnewaddress(const RpcRequest& req, wallet::Wallet* wallet);

/// sendtoaddress(addr, amount): send coins to an address.
RpcResponse rpc_sendtoaddress(const RpcRequest& req, wallet::Wallet* wallet);

/// listtransactions(count, skip): list recent transaction history.
RpcResponse rpc_listtransactions(const RpcRequest& req, wallet::Wallet* wallet);

/// listunspent(minconf, maxconf): list unspent transaction outputs.
RpcResponse rpc_listunspent(const RpcRequest& req, wallet::Wallet* wallet);

/// dumpprivkey(addr): export a private key in WIF format.
RpcResponse rpc_dumpprivkey(const RpcRequest& req, wallet::Wallet* wallet);

/// importprivkey(wif): import a private key.
RpcResponse rpc_importprivkey(const RpcRequest& req, wallet::Wallet* wallet);

/// Register all wallet RPC commands with the server.
/// The wallet pointer may be null if no wallet is loaded.
void register_wallet_rpcs(RpcServer& server, wallet::Wallet* wallet);

} // namespace rpc

#endif // FTC_RPC_WALLET_RPC_H
