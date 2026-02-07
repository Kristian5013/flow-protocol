#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Signature verification cache
// ---------------------------------------------------------------------------
// Caches the result of successful signature verifications so that re-checking
// the same (pubkey, sighash, signature) tuple during block connection or
// mempool acceptance can be skipped.
//
// Thread safety: uses a shared_mutex for concurrent reader access; writers
// acquire an exclusive lock.  When the cache reaches capacity, 50% of entries
// are evicted at random to amortise eviction cost.
//
// Cache key:  keccak256(pubkey || sighash || signature)
// ---------------------------------------------------------------------------

#include "core/sync.h"
#include "core/types.h"
#include "crypto/keccak.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

namespace consensus {

/// Thread-safe signature verification cache.
class SigCache {
public:
    /// Default maximum number of entries in the cache.
    static constexpr size_t DEFAULT_MAX_SIZE = 32'000;

    /// Construct a cache that holds at most @p max_size entries.
    explicit SigCache(size_t max_size = DEFAULT_MAX_SIZE);

    ~SigCache() = default;

    // Non-copyable, non-movable (contains a mutex).
    SigCache(const SigCache&) = delete;
    SigCache& operator=(const SigCache&) = delete;
    SigCache(SigCache&&) = delete;
    SigCache& operator=(SigCache&&) = delete;

    /// Check whether the given cache entry (a precomputed key) is already
    /// present.  Returns true if the signature was previously validated and
    /// cached.
    ///
    /// This is a shared (read) lock operation and can proceed concurrently
    /// with other contains() calls.
    [[nodiscard]] bool contains(const core::uint256& entry) const;

    /// Insert a cache entry after a successful signature verification.
    /// If the cache is at capacity, approximately 50% of existing entries
    /// are evicted at random before the new entry is inserted.
    void insert(const core::uint256& entry);

    /// Compute the cache key for a (pubkey, sighash, signature) tuple.
    ///
    /// The key is:  keccak256(pubkey || hash || sig)
    ///
    /// @param pubkey  The serialised public key bytes.
    /// @param hash    The signature hash (sighash) that was signed.
    /// @param sig     The serialised signature bytes.
    /// @returns A uint256 suitable for use with contains() / insert().
    [[nodiscard]] static core::uint256 compute_entry(
        std::span<const uint8_t> pubkey,
        const core::uint256& hash,
        std::span<const uint8_t> sig);

    /// Return the current number of cached entries.
    [[nodiscard]] size_t size() const;

    /// Return the configured maximum cache size.
    [[nodiscard]] size_t max_size() const noexcept { return max_size_; }

private:
    /// Evict approximately half of the cache entries at random.
    /// Must be called with the exclusive lock held.
    void evict_half();

    size_t max_size_;

    // The map stores cache keys; the mapped value is unused (we just need
    // set membership), but unordered_map is a convenient hash table that
    // provides O(1) lookup.  The value is a dummy uint8_t to minimise
    // memory overhead.
    mutable core::SharedMutex mutex_{"sigcache"};
    std::unordered_map<core::uint256, uint8_t> map_;
};

/// Return a reference to the process-wide singleton SigCache instance.
SigCache& get_sig_cache();

}  // namespace consensus
