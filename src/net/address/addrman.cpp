// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net/address/addrman.h"
#include "core/logging.h"
#include "core/random.h"
#include "core/time.h"
#include "crypto/keccak.h"
#include "crypto/siphash.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <numeric>

namespace net {

// ===================================================================
// Internal constants and helpers
// ===================================================================

namespace {

/// Seconds per day.
constexpr int64_t SECONDS_PER_DAY = 86400;

/// Maximum age in seconds before an address is considered stale.
constexpr int64_t HORIZON_SECONDS = AddrMan::HORIZON_DAYS * SECONDS_PER_DAY;

/// Minimum time between counting connection attempts (seconds).
constexpr int64_t MIN_ATTEMPT_INTERVAL = 60;

/// Build a lookup key string from an AddressWithPort.
std::string make_key(const AddressWithPort& addr) {
    return addr.addr.to_string() + ":" + std::to_string(addr.port);
}

/// Compute a Keccak-256-based bucket hash.
/// Hashes: key || group_data || extra into a uint256, then reduces mod range.
uint64_t hash_for_bucket(const core::uint256& key,
                         std::span<const uint8_t> data) {
    crypto::Keccak256Hasher hasher;
    hasher.write(std::span<const uint8_t>(key.data(), 32));
    hasher.write(data);
    core::uint256 digest = hasher.finalize();

    // Use the first 8 bytes of the digest as a uint64_t (little-endian).
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= static_cast<uint64_t>(digest.data()[i]) << (8 * i);
    }
    return result;
}

}  // anonymous namespace

// ===================================================================
// AddrInfo methods
// ===================================================================

bool AddrMan::AddrInfo::is_terrible(int64_t now) const noexcept {
    // Never connected and learned too long ago.
    if (last_try == 0 && addr.timestamp > 0 &&
        (now - addr.timestamp) > HORIZON_SECONDS) {
        return true;
    }

    // Too many consecutive failures.
    if (attempts >= AddrMan::MAX_RETRIES && last_success == 0) {
        return true;
    }

    // Failed too many times with last success too long ago.
    if (attempts >= AddrMan::MAX_RETRIES &&
        (now - last_success) > HORIZON_SECONDS) {
        return true;
    }

    // Last attempt was very long ago and it was a failure.
    if (last_try > 0 && (now - last_try) > HORIZON_SECONDS && last_success == 0) {
        return true;
    }

    return false;
}

double AddrMan::AddrInfo::get_chance(int64_t now) const noexcept {
    double chance = 1.0;

    // Reduce chance based on time since last attempt.
    int64_t since_last_try = std::max(now - last_try, int64_t{0});

    // Penalize addresses that have been attempted recently.
    if (since_last_try < 600) {
        chance *= 0.01;
    }

    // Exponential back-off per failed attempt (factor 0.66 per attempt).
    for (int i = 0; i < attempts; ++i) {
        chance *= 0.66;
    }

    // Boost addresses that have been successfully connected.
    if (last_success > 0) {
        int64_t since_success = std::max(now - last_success, int64_t{0});
        if (since_success < 3600) {
            chance *= 4.0;
        } else if (since_success < SECONDS_PER_DAY) {
            chance *= 2.0;
        }
    }

    return std::max(chance, 0.0001);
}

// ===================================================================
// AddrMan lifecycle
// ===================================================================

AddrMan::AddrMan() : AddrMan(core::uint256{}) {
    // Generate a cryptographically random key.
    core::get_random_bytes(std::span<uint8_t>(key_.data(), 32));
}

AddrMan::AddrMan(core::uint256 key)
    : key_(std::move(key))
    , new_buckets_(NEW_BUCKET_COUNT, std::vector<int>(BUCKET_SIZE, -1))
    , tried_buckets_(TRIED_BUCKET_COUNT, std::vector<int>(BUCKET_SIZE, -1)) {
    LOG_DEBUG(core::LogCategory::NET, "AddrMan initialized");
}

AddrMan::~AddrMan() = default;

AddrMan::AddrMan(AddrMan&& other) noexcept {
    std::unique_lock lock(other.mutex_);
    key_            = std::move(other.key_);
    map_info_       = std::move(other.map_info_);
    map_addr_       = std::move(other.map_addr_);
    next_id_        = other.next_id_;
    tried_count_    = other.tried_count_;
    new_count_      = other.new_count_;
    new_buckets_    = std::move(other.new_buckets_);
    tried_buckets_  = std::move(other.tried_buckets_);
}

AddrMan& AddrMan::operator=(AddrMan&& other) noexcept {
    if (this != &other) {
        std::unique_lock lock1(mutex_, std::defer_lock);
        std::unique_lock lock2(other.mutex_, std::defer_lock);
        std::lock(lock1, lock2);

        key_            = std::move(other.key_);
        map_info_       = std::move(other.map_info_);
        map_addr_       = std::move(other.map_addr_);
        next_id_        = other.next_id_;
        tried_count_    = other.tried_count_;
        new_count_      = other.new_count_;
        new_buckets_    = std::move(other.new_buckets_);
        tried_buckets_  = std::move(other.tried_buckets_);
    }
    return *this;
}

// ===================================================================
// Bucket computation
// ===================================================================

int AddrMan::get_new_bucket(const AddressWithPort& addr,
                            const NetAddress& source) const {
    // Hash(key, addr_group, source_group) mod NEW_BUCKET_COUNT.
    uint16_t addr_group = addr.addr.get_group_key();
    uint16_t src_group  = source.get_group_key();

    uint8_t data[8];
    data[0] = static_cast<uint8_t>(addr_group >> 8);
    data[1] = static_cast<uint8_t>(addr_group & 0xFF);
    data[2] = static_cast<uint8_t>(src_group >> 8);
    data[3] = static_cast<uint8_t>(src_group & 0xFF);
    // Include port for additional entropy.
    data[4] = static_cast<uint8_t>(addr.port >> 8);
    data[5] = static_cast<uint8_t>(addr.port & 0xFF);
    data[6] = 0; // table type: new = 0
    data[7] = 0;

    uint64_t h = hash_for_bucket(key_, std::span<const uint8_t>(data, 8));
    return static_cast<int>(h % NEW_BUCKET_COUNT);
}

int AddrMan::get_tried_bucket(const AddressWithPort& addr) const {
    // Hash(key, addr_group, full_addr) mod TRIED_BUCKET_COUNT.
    auto addr_str = addr.addr.to_string();
    uint16_t group = addr.addr.get_group_key();

    // Build hash input: group (2 bytes) + addr string bytes + table marker.
    std::vector<uint8_t> data;
    data.reserve(2 + addr_str.size() + 1);
    data.push_back(static_cast<uint8_t>(group >> 8));
    data.push_back(static_cast<uint8_t>(group & 0xFF));
    data.insert(data.end(), addr_str.begin(), addr_str.end());
    data.push_back(1); // table type: tried = 1

    uint64_t h = hash_for_bucket(key_, std::span<const uint8_t>(data));
    return static_cast<int>(h % TRIED_BUCKET_COUNT);
}

int AddrMan::get_bucket_position(int bucket, const AddressWithPort& addr) const {
    auto key_str = make_key(addr);

    uint8_t data[36];
    // bucket as 4 bytes (LE).
    data[0] = static_cast<uint8_t>(bucket & 0xFF);
    data[1] = static_cast<uint8_t>((bucket >> 8) & 0xFF);
    data[2] = static_cast<uint8_t>((bucket >> 16) & 0xFF);
    data[3] = static_cast<uint8_t>((bucket >> 24) & 0xFF);

    size_t copy_len = std::min(key_str.size(), size_t{32});
    std::memcpy(data + 4, key_str.data(), copy_len);
    size_t total = 4 + copy_len;

    uint64_t h = hash_for_bucket(key_, std::span<const uint8_t>(data, total));
    return static_cast<int>(h % BUCKET_SIZE);
}

// ===================================================================
// Internal helpers
// ===================================================================

int AddrMan::find(const AddressWithPort& addr) const {
    std::string key = make_key(addr);
    auto it = map_addr_.find(key);
    if (it != map_addr_.end()) {
        return it->second;
    }
    return -1;
}

int AddrMan::create(const AddressWithPort& addr, const NetAddress& source) {
    int id = next_id_++;
    AddrInfo info;
    info.addr = addr;
    info.source = source;
    info.ref_count = 0;
    info.in_tried = false;

    map_info_[id] = std::move(info);
    map_addr_[make_key(addr)] = id;
    return id;
}

void AddrMan::delete_entry(int id) {
    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    // Remove from address lookup.
    std::string key = make_key(it->second.addr);
    map_addr_.erase(key);

    if (it->second.in_tried) {
        --tried_count_;
    }

    map_info_.erase(it);
}

void AddrMan::clear_new(int id) {
    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    AddrInfo& info = it->second;

    // Remove from all new-table buckets.
    for (int bucket = 0; bucket < NEW_BUCKET_COUNT; ++bucket) {
        for (int pos = 0; pos < BUCKET_SIZE; ++pos) {
            if (new_buckets_[bucket][pos] == id) {
                new_buckets_[bucket][pos] = -1;
                --info.ref_count;
                if (info.ref_count <= 0) {
                    if (!info.in_tried) {
                        --new_count_;
                    }
                    break;
                }
            }
        }
        if (info.ref_count <= 0) break;
    }

    info.ref_count = 0;
}

void AddrMan::make_tried(int id) {
    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    AddrInfo& info = it->second;

    // Remove from the new table first.
    clear_new(id);

    // Find a spot in the tried table.
    int bucket = get_tried_bucket(info.addr);
    int pos = get_bucket_position(bucket, info.addr);

    // If the position is occupied, evict the old entry.
    if (tried_buckets_[bucket][pos] != -1) {
        int evict_id = tried_buckets_[bucket][pos];
        // Move the evicted entry back to new.
        auto evict_it = map_info_.find(evict_id);
        if (evict_it != map_info_.end()) {
            evict_it->second.in_tried = false;
            --tried_count_;
            ++new_count_;

            // Place evicted entry into a new-table bucket.
            int new_bucket = get_new_bucket(evict_it->second.addr,
                                            evict_it->second.source);
            int new_pos = get_bucket_position(new_bucket, evict_it->second.addr);
            if (new_buckets_[new_bucket][new_pos] == -1) {
                new_buckets_[new_bucket][new_pos] = evict_id;
                evict_it->second.ref_count = 1;
            } else {
                // Collision -- just leave with ref_count 0; will be collected later.
                evict_it->second.ref_count = 0;
            }
        }
    }

    tried_buckets_[bucket][pos] = id;
    info.in_tried = true;
    ++tried_count_;
}

void AddrMan::evict_tried(int bucket) {
    // Find the oldest-last-success entry in this bucket.
    int oldest_id = -1;
    int64_t oldest_time = std::numeric_limits<int64_t>::max();

    for (int pos = 0; pos < BUCKET_SIZE; ++pos) {
        int id = tried_buckets_[bucket][pos];
        if (id == -1) continue;

        auto it = map_info_.find(id);
        if (it == map_info_.end()) {
            tried_buckets_[bucket][pos] = -1;
            continue;
        }

        if (it->second.last_success < oldest_time) {
            oldest_time = it->second.last_success;
            oldest_id = id;
        }
    }

    if (oldest_id != -1) {
        // Remove from the tried bucket.
        for (int pos = 0; pos < BUCKET_SIZE; ++pos) {
            if (tried_buckets_[bucket][pos] == oldest_id) {
                tried_buckets_[bucket][pos] = -1;
                break;
            }
        }

        auto it = map_info_.find(oldest_id);
        if (it != map_info_.end()) {
            it->second.in_tried = false;
            --tried_count_;
            ++new_count_;

            // Place back into a new-table bucket.
            int new_bucket = get_new_bucket(it->second.addr, it->second.source);
            int new_pos = get_bucket_position(new_bucket, it->second.addr);
            if (new_buckets_[new_bucket][new_pos] == -1) {
                new_buckets_[new_bucket][new_pos] = oldest_id;
                it->second.ref_count = 1;
            } else {
                it->second.ref_count = 0;
            }
        }
    }
}

// ===================================================================
// Public API
// ===================================================================

bool AddrMan::add(const AddressWithPort& addr, const NetAddress& source) {
    std::unique_lock lock(mutex_);

    if (!addr.addr.is_valid()) return false;
    if (!addr.addr.is_routable()) return false;

    // Check total capacity.
    if (static_cast<int>(map_info_.size()) >= MAX_ADDRESSES) {
        return false;
    }

    int existing_id = find(addr);
    if (existing_id != -1) {
        // Already known.  Update timestamp if the new info is fresher.
        auto it = map_info_.find(existing_id);
        if (it != map_info_.end()) {
            if (addr.timestamp > 0 && addr.timestamp > it->second.addr.timestamp) {
                it->second.addr.timestamp = addr.timestamp;
            }
            if (addr.services != 0) {
                it->second.addr.services |= addr.services;
            }
            // If this address is terrible but someone (DNS seeds, peer gossip)
            // is telling us about it again with a fresh timestamp, give it
            // another chance by resetting the attempt counter.
            int64_t now = core::get_time();
            if (it->second.is_terrible(now) && addr.timestamp > 0 &&
                (now - addr.timestamp) < SECONDS_PER_DAY) {
                it->second.attempts = 0;
                it->second.last_try = 0;
                LOG_DEBUG(core::LogCategory::NET,
                          "AddrMan: reset attempts for re-added address " +
                          addr.to_string());
            }
        }
        return false;
    }

    // Create a new entry.
    int id = create(addr, source);

    // Place into the new table.
    int bucket = get_new_bucket(addr, source);
    int pos = get_bucket_position(bucket, addr);

    if (new_buckets_[bucket][pos] != -1) {
        // Position is occupied.  Check if the existing entry is terrible.
        int old_id = new_buckets_[bucket][pos];
        auto old_it = map_info_.find(old_id);
        int64_t now = core::get_time();
        if (old_it != map_info_.end() && old_it->second.is_terrible(now)) {
            // Evict the terrible entry.
            clear_new(old_id);
            delete_entry(old_id);
        } else {
            // Cannot place -- discard the new entry.
            delete_entry(id);
            return false;
        }
    }

    new_buckets_[bucket][pos] = id;
    auto it = map_info_.find(id);
    if (it != map_info_.end()) {
        it->second.ref_count = 1;
    }
    ++new_count_;

    LOG_DEBUG(core::LogCategory::NET,
              "AddrMan: added " + addr.to_string() + " (new table, bucket " +
              std::to_string(bucket) + ")");
    return true;
}

size_t AddrMan::add(const std::vector<AddressWithPort>& addrs,
                    const NetAddress& source) {
    size_t count = 0;
    for (const auto& addr : addrs) {
        if (add(addr, source)) {
            ++count;
        }
    }
    return count;
}

void AddrMan::mark_good(const AddressWithPort& addr, int64_t now) {
    std::unique_lock lock(mutex_);

    int id = find(addr);
    if (id == -1) return;

    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    AddrInfo& info = it->second;
    info.last_success = now;
    info.last_try = now;
    info.attempts = 0;

    // Update the timestamp.
    if (now > info.addr.timestamp) {
        info.addr.timestamp = now;
    }

    // Promote to tried table if not already there.
    if (!info.in_tried) {
        make_tried(id);
        LOG_DEBUG(core::LogCategory::NET,
                  "AddrMan: promoted " + addr.to_string() + " to tried table");
    }
}

void AddrMan::mark_attempt(const AddressWithPort& addr, int64_t now) {
    std::unique_lock lock(mutex_);

    int id = find(addr);
    if (id == -1) return;

    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    AddrInfo& info = it->second;

    // Rate-limit attempt counting.
    if (now - info.last_count_attempt >= MIN_ATTEMPT_INTERVAL) {
        info.last_count_attempt = now;
        ++info.attempts;
    }
    info.last_try = now;
}

void AddrMan::mark_connected(const AddressWithPort& addr, int64_t now) {
    std::unique_lock lock(mutex_);

    int id = find(addr);
    if (id == -1) return;

    auto it = map_info_.find(id);
    if (it == map_info_.end()) return;

    AddrInfo& info = it->second;

    // Only update timestamp if this is a meaningful update.
    int64_t update_interval = 20 * 60; // 20 minutes
    if (now - info.addr.timestamp > update_interval) {
        info.addr.timestamp = now;
    }
}

std::optional<AddressWithPort> AddrMan::select(bool new_only) const {
    std::unique_lock lock(mutex_);

    if (map_info_.empty()) return std::nullopt;

    int64_t now = core::get_time();

    // Decide whether to pick from new or tried table.
    // If new_only is true, always pick from new.
    // Otherwise, use a 50/50 chance if both tables have entries.
    bool use_new = new_only;
    if (!new_only) {
        if (tried_count_ == 0) {
            use_new = true;
        } else if (new_count_ == 0) {
            use_new = false;
        } else {
            // 50% chance of picking from new table, biased by table sizes.
            double new_chance = static_cast<double>(new_count_) /
                                (new_count_ + tried_count_);
            uint64_t r = core::get_random_range(1000);
            use_new = (r < static_cast<uint64_t>(new_chance * 1000));
        }
    }

    // Weighted random selection.  With a sparse table (few addresses
    // in 65k+ slots) more iterations are needed for random bucket
    // selection to find populated slots before falling back to linear scan.
    constexpr int MAX_ITERATIONS = 300;

    for (int iter = 0; iter < MAX_ITERATIONS; ++iter) {
        if (use_new) {
            // Pick a random new-table bucket and position.
            int bucket = static_cast<int>(core::get_random_range(NEW_BUCKET_COUNT));
            int pos = static_cast<int>(core::get_random_range(BUCKET_SIZE));
            int id = new_buckets_[bucket][pos];
            if (id == -1) continue;

            auto it = map_info_.find(id);
            if (it == map_info_.end()) continue;

            const AddrInfo& info = it->second;
            if (info.is_terrible(now)) continue;

            // Accept with probability proportional to chance.
            double chance = info.get_chance(now);
            uint64_t r = core::get_random_range(1000000);
            if (r < static_cast<uint64_t>(chance * 1000000)) {
                return info.addr;
            }
        } else {
            // Pick a random tried-table bucket and position.
            int bucket = static_cast<int>(core::get_random_range(TRIED_BUCKET_COUNT));
            int pos = static_cast<int>(core::get_random_range(BUCKET_SIZE));
            int id = tried_buckets_[bucket][pos];
            if (id == -1) continue;

            auto it = map_info_.find(id);
            if (it == map_info_.end()) continue;

            const AddrInfo& info = it->second;
            if (info.is_terrible(now)) continue;

            double chance = info.get_chance(now);
            uint64_t r = core::get_random_range(1000000);
            if (r < static_cast<uint64_t>(chance * 1000000)) {
                return info.addr;
            }
        }
    }

    // Fallback: return any non-terrible address.
    for (const auto& [id, info] : map_info_) {
        if (new_only && info.in_tried) continue;
        if (!info.is_terrible(now)) {
            return info.addr;
        }
    }

    return std::nullopt;
}

std::vector<AddressWithPort> AddrMan::get_addr(size_t max_count,
                                                Network filter) const {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();
    std::vector<AddressWithPort> result;
    result.reserve(std::min(max_count, map_info_.size()));

    for (const auto& [id, info] : map_info_) {
        if (info.addr.addr.get_network() != filter) continue;
        if (info.is_terrible(now)) continue;
        result.push_back(info.addr);
    }

    // Shuffle to avoid deterministic ordering.
    for (size_t i = result.size(); i > 1; --i) {
        size_t j = static_cast<size_t>(core::get_random_range(i));
        std::swap(result[i - 1], result[j]);
    }

    // Truncate to max_count.
    size_t limit = std::min(max_count, MAX_GET_ADDR);
    if (result.size() > limit) {
        result.resize(limit);
    }

    return result;
}

std::vector<AddressWithPort> AddrMan::get_addr_all(size_t max_count) const {
    std::unique_lock lock(mutex_);

    int64_t now = core::get_time();
    std::vector<AddressWithPort> result;
    result.reserve(std::min(max_count, map_info_.size()));

    for (const auto& [id, info] : map_info_) {
        if (info.is_terrible(now)) continue;
        result.push_back(info.addr);
    }

    // Shuffle to avoid deterministic ordering.
    for (size_t i = result.size(); i > 1; --i) {
        size_t j = static_cast<size_t>(core::get_random_range(i));
        std::swap(result[i - 1], result[j]);
    }

    size_t limit = std::min(max_count, MAX_GET_ADDR);
    if (result.size() > limit) {
        result.resize(limit);
    }

    return result;
}

size_t AddrMan::size() const {
    std::unique_lock lock(mutex_);
    return map_info_.size();
}

size_t AddrMan::size_new() const {
    std::unique_lock lock(mutex_);
    return static_cast<size_t>(std::max(new_count_, 0));
}

size_t AddrMan::size_tried() const {
    std::unique_lock lock(mutex_);
    return static_cast<size_t>(std::max(tried_count_, 0));
}

void AddrMan::clear() {
    std::unique_lock lock(mutex_);

    map_info_.clear();
    map_addr_.clear();
    next_id_ = 0;
    tried_count_ = 0;
    new_count_ = 0;

    // Reset all bucket entries to -1.
    for (auto& bucket : new_buckets_) {
        std::fill(bucket.begin(), bucket.end(), -1);
    }
    for (auto& bucket : tried_buckets_) {
        std::fill(bucket.begin(), bucket.end(), -1);
    }

    LOG_DEBUG(core::LogCategory::NET, "AddrMan: cleared all addresses");
}

}  // namespace net
