// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/notify.h"
#include "core/logging.h"

#include <algorithm>

namespace wallet {

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

CallbackId WalletNotify::on_transaction(TxCallback callback) {
    std::lock_guard lock(mutex_);
    auto id = allocate_id();
    tx_callbacks_.push_back({id, std::move(callback)});
    LOG_DEBUG(core::LogCategory::WALLET,
              "Registered transaction callback id=" + std::to_string(id));
    return id;
}

CallbackId WalletNotify::on_block(BlockCallback callback) {
    std::lock_guard lock(mutex_);
    auto id = allocate_id();
    block_callbacks_.push_back({id, std::move(callback)});
    LOG_DEBUG(core::LogCategory::WALLET,
              "Registered block callback id=" + std::to_string(id));
    return id;
}

CallbackId WalletNotify::on_balance_change(BalanceCallback callback) {
    std::lock_guard lock(mutex_);
    auto id = allocate_id();
    balance_callbacks_.push_back({id, std::move(callback)});
    LOG_DEBUG(core::LogCategory::WALLET,
              "Registered balance callback id=" + std::to_string(id));
    return id;
}

CallbackId WalletNotify::on_new_address(AddressCallback callback) {
    std::lock_guard lock(mutex_);
    auto id = allocate_id();
    address_callbacks_.push_back({id, std::move(callback)});
    LOG_DEBUG(core::LogCategory::WALLET,
              "Registered new address callback id=" + std::to_string(id));
    return id;
}

// ---------------------------------------------------------------------------
// Unregistration
// ---------------------------------------------------------------------------

void WalletNotify::remove_callback(CallbackId id) {
    std::lock_guard lock(mutex_);

    auto remove_from = [id](auto& vec) {
        vec.erase(
            std::remove_if(vec.begin(), vec.end(),
                           [id](const auto& entry) {
                               return entry.id == id;
                           }),
            vec.end());
    };

    remove_from(tx_callbacks_);
    remove_from(block_callbacks_);
    remove_from(balance_callbacks_);
    remove_from(address_callbacks_);

    LOG_DEBUG(core::LogCategory::WALLET,
              "Removed callback id=" + std::to_string(id));
}

void WalletNotify::clear_all() {
    std::lock_guard lock(mutex_);
    tx_callbacks_.clear();
    block_callbacks_.clear();
    balance_callbacks_.clear();
    address_callbacks_.clear();
    LOG_DEBUG(core::LogCategory::WALLET, "Cleared all notification callbacks");
}

// ---------------------------------------------------------------------------
// Notification dispatch
// ---------------------------------------------------------------------------

void WalletNotify::notify_transaction(const core::uint256& txid,
                                       int confirmations) {
    // Copy callbacks under lock, then invoke outside the lock to avoid
    // potential deadlocks if a callback tries to register/unregister.
    std::vector<TxCallback> callbacks;
    {
        std::lock_guard lock(mutex_);
        callbacks.reserve(tx_callbacks_.size());
        for (const auto& entry : tx_callbacks_) {
            callbacks.push_back(entry.callback);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(txid, confirmations);
        } catch (const std::exception& e) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Exception in transaction callback: " +
                      std::string(e.what()));
        } catch (...) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Unknown exception in transaction callback");
        }
    }
}

void WalletNotify::notify_block(int height, const core::uint256& hash) {
    std::vector<BlockCallback> callbacks;
    {
        std::lock_guard lock(mutex_);
        callbacks.reserve(block_callbacks_.size());
        for (const auto& entry : block_callbacks_) {
            callbacks.push_back(entry.callback);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(height, hash);
        } catch (const std::exception& e) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Exception in block callback: " +
                      std::string(e.what()));
        } catch (...) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Unknown exception in block callback");
        }
    }
}

void WalletNotify::notify_balance_change(primitives::Amount new_balance) {
    std::vector<BalanceCallback> callbacks;
    {
        std::lock_guard lock(mutex_);
        callbacks.reserve(balance_callbacks_.size());
        for (const auto& entry : balance_callbacks_) {
            callbacks.push_back(entry.callback);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(new_balance);
        } catch (const std::exception& e) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Exception in balance callback: " +
                      std::string(e.what()));
        } catch (...) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Unknown exception in balance callback");
        }
    }
}

void WalletNotify::notify_new_address(const std::string& address) {
    std::vector<AddressCallback> callbacks;
    {
        std::lock_guard lock(mutex_);
        callbacks.reserve(address_callbacks_.size());
        for (const auto& entry : address_callbacks_) {
            callbacks.push_back(entry.callback);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(address);
        } catch (const std::exception& e) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Exception in address callback: " +
                      std::string(e.what()));
        } catch (...) {
            LOG_ERROR(core::LogCategory::WALLET,
                      "Unknown exception in address callback");
        }
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

size_t WalletNotify::callback_count() const {
    std::lock_guard lock(mutex_);
    return tx_callbacks_.size() + block_callbacks_.size() +
           balance_callbacks_.size() + address_callbacks_.size();
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

CallbackId WalletNotify::allocate_id() {
    return next_id_++;
}

} // namespace wallet
