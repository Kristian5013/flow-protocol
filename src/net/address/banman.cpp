// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/address/banman.h"
#include "core/logging.h"
#include "core/time.h"

#include <algorithm>
#include <utility>

namespace net {

// ===================================================================
// BanEntry
// ===================================================================

bool BanMan::BanEntry::is_expired(int64_t now) const noexcept {
    // ban_until == 0 means permanent (never expires).
    if (ban_until == 0) return false;
    return now >= ban_until;
}

// ===================================================================
// BanMan lifecycle
// ===================================================================

BanMan::BanMan() {
    LOG_DEBUG(core::LogCategory::NET, "BanMan initialized");
}

BanMan::~BanMan() = default;

void BanMan::set_change_callback(BanChangeCallback cb) {
    std::unique_lock lock(mutex_);
    change_callback_ = std::move(cb);
}

// ===================================================================
// Internal helpers
// ===================================================================

void BanMan::notify_change() const {
    // The callback is invoked without the lock held to prevent deadlocks.
    // Callers must copy the callback under the lock, then invoke outside.
    // However, for simplicity and because the callback is expected to be
    // lightweight (e.g., scheduling a persist), we invoke inside the lock
    // with the understanding that the callback must not re-enter BanMan.
    if (change_callback_) {
        change_callback_();
    }
}

int64_t BanMan::compute_ban_until(int64_t now, int64_t duration_seconds) {
    if (duration_seconds <= 0) {
        return 0; // permanent
    }
    // Clamp to maximum.
    if (duration_seconds > MAX_BAN_DURATION) {
        duration_seconds = MAX_BAN_DURATION;
    }
    return now + duration_seconds;
}

// ===================================================================
// Ban operations
// ===================================================================

void BanMan::ban(const NetAddress& addr, int64_t duration_seconds,
                 const std::string& reason) {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();
    std::string key = addr.to_string();

    // Check if already banned -- extend if the new ban is longer.
    auto it = banned_.find(key);
    if (it != banned_.end()) {
        int64_t new_until = compute_ban_until(now, duration_seconds);
        BanEntry& existing = it->second.second;
        // Permanent ban (0) always wins.  Otherwise, take the later expiry.
        if (new_until == 0 || (existing.ban_until != 0 && new_until > existing.ban_until)) {
            existing.ban_until = new_until;
            existing.reason = reason;
            LOG_INFO(core::LogCategory::NET,
                     "BanMan: extended ban on " + key + " reason: " + reason);
            notify_change();
        }
        return;
    }

    BanEntry entry;
    entry.ban_created = now;
    entry.ban_until = compute_ban_until(now, duration_seconds);
    entry.reason = reason;

    banned_.emplace(key, std::make_pair(addr, std::move(entry)));

    LOG_INFO(core::LogCategory::NET,
             "BanMan: banned " + key + " reason: " + reason);
    notify_change();
}

void BanMan::ban_subnet(const Subnet& subnet, int64_t duration_seconds,
                        const std::string& reason) {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();

    // Check if this exact subnet is already banned.
    for (auto& [existing_subnet, existing_entry] : banned_subnets_) {
        if (existing_subnet == subnet) {
            int64_t new_until = compute_ban_until(now, duration_seconds);
            if (new_until == 0 ||
                (existing_entry.ban_until != 0 && new_until > existing_entry.ban_until)) {
                existing_entry.ban_until = new_until;
                existing_entry.reason = reason;
                LOG_INFO(core::LogCategory::NET,
                         "BanMan: extended subnet ban on " + subnet.to_string() +
                         " reason: " + reason);
                notify_change();
            }
            return;
        }
    }

    BanEntry entry;
    entry.ban_created = now;
    entry.ban_until = compute_ban_until(now, duration_seconds);
    entry.reason = reason;

    banned_subnets_.emplace_back(subnet, std::move(entry));

    LOG_INFO(core::LogCategory::NET,
             "BanMan: banned subnet " + subnet.to_string() + " reason: " + reason);
    notify_change();
}

bool BanMan::is_banned(const NetAddress& addr) const {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();

    // Check direct address bans.
    std::string key = addr.to_string();
    auto it = banned_.find(key);
    if (it != banned_.end()) {
        if (!it->second.second.is_expired(now)) {
            return true;
        }
    }

    // Check subnet bans.
    for (const auto& [subnet, entry] : banned_subnets_) {
        if (entry.is_expired(now)) continue;
        if (subnet.contains(addr)) {
            return true;
        }
    }

    return false;
}

bool BanMan::is_address_banned(const NetAddress& addr) const {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();
    std::string key = addr.to_string();
    auto it = banned_.find(key);
    if (it != banned_.end()) {
        return !it->second.second.is_expired(now);
    }
    return false;
}

bool BanMan::is_subnet_banned(const NetAddress& addr) const {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();
    for (const auto& [subnet, entry] : banned_subnets_) {
        if (entry.is_expired(now)) continue;
        if (subnet.contains(addr)) {
            return true;
        }
    }
    return false;
}

void BanMan::unban(const NetAddress& addr) {
    std::unique_lock lock(mutex_);

    std::string key = addr.to_string();
    auto it = banned_.find(key);
    if (it != banned_.end()) {
        banned_.erase(it);
        LOG_INFO(core::LogCategory::NET, "BanMan: unbanned " + key);
        notify_change();
    }
}

void BanMan::unban_subnet(const Subnet& subnet) {
    std::unique_lock lock(mutex_);

    auto it = std::remove_if(banned_subnets_.begin(), banned_subnets_.end(),
        [&subnet](const std::pair<Subnet, BanEntry>& entry) {
            return entry.first == subnet;
        });

    if (it != banned_subnets_.end()) {
        banned_subnets_.erase(it, banned_subnets_.end());
        LOG_INFO(core::LogCategory::NET,
                 "BanMan: unbanned subnet " + subnet.to_string());
        notify_change();
    }
}

size_t BanMan::sweep_expired(int64_t now) {
    std::unique_lock lock(mutex_);

    size_t removed = 0;

    // Sweep direct address bans.
    for (auto it = banned_.begin(); it != banned_.end(); ) {
        if (it->second.second.is_expired(now)) {
            LOG_DEBUG(core::LogCategory::NET,
                      "BanMan: expired ban on " + it->first);
            it = banned_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    // Sweep subnet bans.
    auto subnet_it = std::remove_if(
        banned_subnets_.begin(), banned_subnets_.end(),
        [now, &removed](const std::pair<Subnet, BanEntry>& entry) {
            if (entry.second.is_expired(now)) {
                ++removed;
                return true;
            }
            return false;
        });

    if (subnet_it != banned_subnets_.end()) {
        banned_subnets_.erase(subnet_it, banned_subnets_.end());
    }

    if (removed > 0) {
        LOG_INFO(core::LogCategory::NET,
                 "BanMan: swept " + std::to_string(removed) + " expired ban(s)");
        notify_change();
    }

    return removed;
}

std::vector<std::pair<NetAddress, BanMan::BanEntry>> BanMan::list_banned() const {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();
    std::vector<std::pair<NetAddress, BanEntry>> result;
    result.reserve(banned_.size());

    for (const auto& [key, pair] : banned_) {
        if (!pair.second.is_expired(now)) {
            result.emplace_back(pair.first, pair.second);
        }
    }

    return result;
}

std::vector<std::pair<Subnet, BanMan::BanEntry>> BanMan::list_banned_subnets() const {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();
    std::vector<std::pair<Subnet, BanEntry>> result;
    result.reserve(banned_subnets_.size());

    for (const auto& [subnet, entry] : banned_subnets_) {
        if (!entry.is_expired(now)) {
            result.emplace_back(subnet, entry);
        }
    }

    return result;
}

size_t BanMan::size() const {
    std::unique_lock lock(mutex_);
    return banned_.size() + banned_subnets_.size();
}

size_t BanMan::size_addresses() const {
    std::unique_lock lock(mutex_);
    return banned_.size();
}

size_t BanMan::size_subnets() const {
    std::unique_lock lock(mutex_);
    return banned_subnets_.size();
}

void BanMan::clear() {
    std::unique_lock lock(mutex_);

    banned_.clear();
    banned_subnets_.clear();

    LOG_INFO(core::LogCategory::NET, "BanMan: cleared all bans");
    notify_change();
}

}  // namespace net
