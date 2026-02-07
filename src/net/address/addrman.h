#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// AddrMan -- address manager with bucketed storage for eclipse resistance.
//
// Maintains a database of known peer addresses, split into "new" (learned
// from gossip) and "tried" (successfully connected) tables.  Bucket
// assignment uses Keccak-256 keyed hashing of address + random nonce to
// provide deterministic-but-unpredictable placement, resisting eclipse
// attacks where an adversary fills our address table with colluding nodes.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "core/types.h"
#include "net/address/netaddress.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace net {

class AddrMan {
public:
    // -- Constants ----------------------------------------------------------

    static constexpr int NEW_BUCKET_COUNT   = 1024;
    static constexpr int TRIED_BUCKET_COUNT = 256;
    static constexpr int BUCKET_SIZE        = 64;
    static constexpr int MAX_ADDRESSES      = 65536;

    /// Maximum number of addresses returned by get_addr().
    static constexpr size_t MAX_GET_ADDR     = 2500;

    /// Number of hours after which an address is considered stale.
    static constexpr int64_t HORIZON_DAYS    = 30;

    /// Maximum number of connection attempts before an address is discarded.
    static constexpr int MAX_RETRIES         = 3;

    /// Minimum interval between connection retries (seconds).
    static constexpr int64_t RETRY_DELAY_BASE = 600;  // 10 minutes

    // -- AddrInfo: per-address metadata ------------------------------------

    struct AddrInfo {
        AddressWithPort addr;
        int64_t last_try       = 0;    // timestamp of last connection attempt
        int64_t last_success   = 0;    // timestamp of last successful connection
        int     attempts       = 0;    // number of failed connection attempts
        NetAddress source;             // who told us about this address
        int     ref_count      = 0;    // number of new-table buckets referencing this
        bool    in_tried       = false; // true if this address is in the tried table
        int64_t last_count_attempt = 0; // last time attempt was counted

        /// Returns true if this address is "terrible" and should be discarded.
        [[nodiscard]] bool is_terrible(int64_t now) const noexcept;

        /// Returns a selection weight (higher = more likely to be selected).
        [[nodiscard]] double get_chance(int64_t now) const noexcept;
    };

    // -- Lifecycle ----------------------------------------------------------

    /// Construct with a random key for bucket assignment.
    AddrMan();

    /// Construct with a specific key (for deterministic testing).
    explicit AddrMan(core::uint256 key);

    ~AddrMan();

    // Non-copyable.
    AddrMan(const AddrMan&) = delete;
    AddrMan& operator=(const AddrMan&) = delete;

    // Movable.
    AddrMan(AddrMan&&) noexcept;
    AddrMan& operator=(AddrMan&&) noexcept;

    // -- Public API ---------------------------------------------------------

    /// Add a new address learned from the given source.
    /// Returns true if the address was actually added (or updated).
    bool add(const AddressWithPort& addr, const NetAddress& source);

    /// Add multiple addresses from the same source.
    /// Returns the number of addresses actually added.
    size_t add(const std::vector<AddressWithPort>& addrs, const NetAddress& source);

    /// Mark an address as successfully connected.
    void mark_good(const AddressWithPort& addr, int64_t now);

    /// Record a connection attempt to this address.
    void mark_attempt(const AddressWithPort& addr, int64_t now);

    /// Record that we are currently connected to this address.
    void mark_connected(const AddressWithPort& addr, int64_t now);

    /// Select an address for connection, using weighted random selection.
    /// If new_only is true, only addresses from the "new" table are returned.
    /// Returns std::nullopt if no suitable address is found.
    [[nodiscard]] std::optional<AddressWithPort> select(bool new_only = false) const;

    /// Return up to max_count addresses, optionally filtered by network type.
    /// Addresses are shuffled before truncation.
    [[nodiscard]] std::vector<AddressWithPort> get_addr(
        size_t max_count, Network filter = Network::IPV4) const;

    /// Return up to max_count addresses without network filtering.
    [[nodiscard]] std::vector<AddressWithPort> get_addr_all(size_t max_count) const;

    /// Return the total number of tracked addresses.
    [[nodiscard]] size_t size() const;

    /// Return the number of addresses in the "new" table.
    [[nodiscard]] size_t size_new() const;

    /// Return the number of addresses in the "tried" table.
    [[nodiscard]] size_t size_tried() const;

    /// Remove all addresses and reset to empty state.
    void clear();

private:
    // -- Bucket computation -------------------------------------------------

    /// Compute the new-table bucket index for an address given its source.
    [[nodiscard]] int get_new_bucket(const AddressWithPort& addr,
                                     const NetAddress& source) const;

    /// Compute the tried-table bucket index for an address.
    [[nodiscard]] int get_tried_bucket(const AddressWithPort& addr) const;

    /// Compute the position within a bucket for an address.
    [[nodiscard]] int get_bucket_position(int bucket, const AddressWithPort& addr) const;

    // -- Internal operations ------------------------------------------------

    /// Move an address from the new table to the tried table.
    void make_tried(int id);

    /// Evict one entry from a tried-table bucket to make room.
    /// The evicted entry is moved back to the new table.
    void evict_tried(int bucket);

    /// Remove an address from all new-table bucket references.
    void clear_new(int id);

    /// Find the internal ID for an address, or -1 if not found.
    [[nodiscard]] int find(const AddressWithPort& addr) const;

    /// Create a new internal entry and return its ID.
    int create(const AddressWithPort& addr, const NetAddress& source);

    /// Delete an entry by its internal ID.
    void delete_entry(int id);

    // -- Data ---------------------------------------------------------------

    core::uint256 key_;   // random nonce for deterministic bucket placement

    /// Map from internal ID to AddrInfo.
    std::unordered_map<int, AddrInfo> map_info_;

    /// Map from address key (string) to internal ID for fast lookup.
    std::unordered_map<std::string, int> map_addr_;

    /// Next internal ID to assign.
    int next_id_ = 0;

    /// Number of entries in the tried table.
    int tried_count_ = 0;

    /// Number of entries in the new table.
    int new_count_ = 0;

    /// New-table buckets: new_buckets_[bucket][position] = entry ID or -1.
    std::vector<std::vector<int>> new_buckets_;

    /// Tried-table buckets: tried_buckets_[bucket][position] = entry ID or -1.
    std::vector<std::vector<int>> tried_buckets_;

    mutable std::mutex mutex_;
};

}  // namespace net
