#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// BanMan -- ban manager for misbehaving peers.
//
// Tracks bans on individual addresses and CIDR subnets.  Provides
// thread-safe ban/unban operations and automatic expiry of time-limited
// bans.  Integration point for the P2P layer's misbehavior scoring.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "net/address/netaddress.h"
#include "net/address/subnet.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace net {

class BanMan {
public:
    // -- Ban entry ----------------------------------------------------------

    struct BanEntry {
        int64_t     ban_created = 0;   // Unix timestamp when ban was created
        int64_t     ban_until   = 0;   // Unix timestamp when ban expires (0 = permanent)
        std::string reason;            // human-readable ban reason

        /// Returns true if this ban has expired relative to the given time.
        [[nodiscard]] bool is_expired(int64_t now) const noexcept;
    };

    /// Default ban duration: 24 hours in seconds.
    static constexpr int64_t DEFAULT_BAN_DURATION = 86400;

    /// Maximum ban duration: 1 year in seconds.
    static constexpr int64_t MAX_BAN_DURATION = 365 * 86400;

    // -- Ban callback type --------------------------------------------------

    /// Optional callback invoked when the ban list changes.
    /// Can be used to persist bans or notify connected components.
    using BanChangeCallback = std::function<void()>;

    // -- Lifecycle ----------------------------------------------------------

    BanMan();
    ~BanMan();

    // Non-copyable.
    BanMan(const BanMan&) = delete;
    BanMan& operator=(const BanMan&) = delete;

    /// Set a callback to be invoked whenever the ban list changes.
    void set_change_callback(BanChangeCallback cb);

    // -- Ban operations -----------------------------------------------------

    /// Ban a single address for the given duration (seconds).
    /// If duration_seconds is 0, the ban is permanent.
    void ban(const NetAddress& addr, int64_t duration_seconds,
             const std::string& reason);

    /// Ban a subnet for the given duration (seconds).
    void ban_subnet(const Subnet& subnet, int64_t duration_seconds,
                    const std::string& reason);

    /// Check if an address is banned (either directly or via a subnet ban).
    [[nodiscard]] bool is_banned(const NetAddress& addr) const;

    /// Check if a specific address has a direct (non-subnet) ban.
    [[nodiscard]] bool is_address_banned(const NetAddress& addr) const;

    /// Check if an address matches any banned subnet.
    [[nodiscard]] bool is_subnet_banned(const NetAddress& addr) const;

    /// Remove a direct address ban.
    void unban(const NetAddress& addr);

    /// Remove a subnet ban.
    void unban_subnet(const Subnet& subnet);

    /// Remove all bans that have expired as of the given time.
    /// Returns the number of bans removed.
    size_t sweep_expired(int64_t now);

    /// Return all currently active address bans.
    [[nodiscard]] std::vector<std::pair<NetAddress, BanEntry>> list_banned() const;

    /// Return all currently active subnet bans.
    [[nodiscard]] std::vector<std::pair<Subnet, BanEntry>> list_banned_subnets() const;

    /// Return the total number of active bans (addresses + subnets).
    [[nodiscard]] size_t size() const;

    /// Return the number of direct address bans.
    [[nodiscard]] size_t size_addresses() const;

    /// Return the number of subnet bans.
    [[nodiscard]] size_t size_subnets() const;

    /// Remove all bans.
    void clear();

private:
    // -- Internal helpers ---------------------------------------------------

    /// Notify the change callback (if set).
    void notify_change() const;

    /// Compute the ban-until timestamp from a duration.
    static int64_t compute_ban_until(int64_t now, int64_t duration_seconds);

    // -- Data ---------------------------------------------------------------

    /// Direct address bans, keyed by address string for O(1) lookup.
    std::unordered_map<std::string, std::pair<NetAddress, BanEntry>> banned_;

    /// Subnet bans -- linear scan required for containment checks.
    std::vector<std::pair<Subnet, BanEntry>> banned_subnets_;

    /// Optional change notification callback.
    BanChangeCallback change_callback_;

    mutable std::mutex mutex_;
};

}  // namespace net
