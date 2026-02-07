#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/types.h"
#include "primitives/amount.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace wallet {

// ---------------------------------------------------------------------------
// WalletNotify -- callbacks for wallet events
// ---------------------------------------------------------------------------
// Provides a notification system for wallet-related events. Components
// (such as the RPC layer, GUI, or wallet scanner) register callbacks that
// are invoked when relevant events occur.
//
// All callbacks are dispatched synchronously on the calling thread.
// Callbacks must be lightweight and non-blocking.
// ---------------------------------------------------------------------------

/// Callback types for wallet notifications.
using TxCallback = std::function<void(const core::uint256& txid,
                                       int confirmations)>;

using BlockCallback = std::function<void(int height,
                                          const core::uint256& hash)>;

using BalanceCallback = std::function<void(primitives::Amount new_balance)>;

using AddressCallback = std::function<void(const std::string& address)>;

/// Unique identifier for a registered callback, used for unregistration.
using CallbackId = uint64_t;

class WalletNotify {
public:
    WalletNotify() = default;

    // -- Registration -------------------------------------------------------

    /// Register a callback to be invoked when a wallet-relevant transaction
    /// is seen (either in a new block or in the mempool).
    /// @returns An ID that can be used to unregister the callback.
    CallbackId on_transaction(TxCallback callback);

    /// Register a callback for new blocks that contain wallet transactions.
    CallbackId on_block(BlockCallback callback);

    /// Register a callback for balance changes.
    CallbackId on_balance_change(BalanceCallback callback);

    /// Register a callback for new address generation.
    CallbackId on_new_address(AddressCallback callback);

    // -- Unregistration -----------------------------------------------------

    /// Remove a previously registered callback by its ID.
    void remove_callback(CallbackId id);

    /// Remove all registered callbacks.
    void clear_all();

    // -- Notification dispatch ----------------------------------------------

    /// Notify all registered transaction callbacks.
    void notify_transaction(const core::uint256& txid,
                            int confirmations);

    /// Notify all registered block callbacks.
    void notify_block(int height, const core::uint256& hash);

    /// Notify all registered balance change callbacks.
    void notify_balance_change(primitives::Amount new_balance);

    /// Notify all registered new address callbacks.
    void notify_new_address(const std::string& address);

    // -- Stats --------------------------------------------------------------

    /// Total number of registered callbacks.
    [[nodiscard]] size_t callback_count() const;

private:
    mutable std::mutex mutex_;
    CallbackId next_id_ = 1;

    struct TxEntry {
        CallbackId id;
        TxCallback callback;
    };

    struct BlockEntry {
        CallbackId id;
        BlockCallback callback;
    };

    struct BalanceEntry {
        CallbackId id;
        BalanceCallback callback;
    };

    struct AddressEntry {
        CallbackId id;
        AddressCallback callback;
    };

    std::vector<TxEntry> tx_callbacks_;
    std::vector<BlockEntry> block_callbacks_;
    std::vector<BalanceEntry> balance_callbacks_;
    std::vector<AddressEntry> address_callbacks_;

    /// Generate the next unique callback ID.
    CallbackId allocate_id();
};

} // namespace wallet
