// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/sigcache.h"

#include "core/logging.h"
#include "core/random.h"
#include "core/sync.h"
#include "core/types.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <vector>

namespace consensus {

// ---------------------------------------------------------------------------
// SigCache construction
// ---------------------------------------------------------------------------

SigCache::SigCache(size_t max_size)
    : max_size_(max_size == 0 ? 1 : max_size)
{
    // Pre-allocate some bucket space to reduce early rehashing.
    map_.reserve(max_size_);
}

// ---------------------------------------------------------------------------
// contains  --  shared (reader) lock
// ---------------------------------------------------------------------------

bool SigCache::contains(const core::uint256& entry) const {
    core::SharedLock lock(mutex_);
    return map_.find(entry) != map_.end();
}

// ---------------------------------------------------------------------------
// insert  --  exclusive (writer) lock
// ---------------------------------------------------------------------------

void SigCache::insert(const core::uint256& entry) {
    // Acquire exclusive lock for the write path.
    // SharedMutex supports lock()/unlock() for exclusive access.
    std::unique_lock<core::SharedMutex> lock(mutex_);

    // If the entry is already present, nothing to do.
    if (map_.find(entry) != map_.end()) {
        return;
    }

    // Evict if at capacity.
    if (map_.size() >= max_size_) {
        evict_half();
    }

    map_.emplace(entry, uint8_t{0});
}

// ---------------------------------------------------------------------------
// compute_entry  --  static, no locking needed
// ---------------------------------------------------------------------------

core::uint256 SigCache::compute_entry(
    std::span<const uint8_t> pubkey,
    const core::uint256& hash,
    std::span<const uint8_t> sig)
{
    // Compute keccak256(pubkey || hash || sig).
    crypto::Keccak256Hasher hasher;
    hasher.write(pubkey);
    hasher.write(hash.data(), hash.size());
    hasher.write(sig);
    return hasher.finalize();
}

// ---------------------------------------------------------------------------
// size  --  shared (reader) lock
// ---------------------------------------------------------------------------

size_t SigCache::size() const {
    core::SharedLock lock(mutex_);
    return map_.size();
}

// ---------------------------------------------------------------------------
// evict_half  --  must be called with exclusive lock held
// ---------------------------------------------------------------------------
// Removes approximately 50% of the cache entries.  Uses random selection
// by iterating through the map and flipping a coin for each entry.  This
// gives O(n) eviction cost amortised over n/2 insertions that triggered it,
// resulting in O(1) amortised cost per insert.
// ---------------------------------------------------------------------------

void SigCache::evict_half() {
    if (map_.empty()) {
        return;
    }

    size_t target_removals = map_.size() / 2;
    if (target_removals == 0) {
        target_removals = 1;
    }

    LOG_DEBUG(core::LogCategory::VALIDATION,
              "SigCache: evicting ~" + std::to_string(target_removals)
              + " of " + std::to_string(map_.size()) + " entries");

    // Use a fast non-cryptographic PRNG for eviction decisions.
    // InsecureRandom auto-seeds from the crypto RNG when constructed with 0.
    core::InsecureRandom rng;

    size_t removed = 0;
    for (auto it = map_.begin(); it != map_.end() && removed < target_removals; ) {
        // 50% chance of removal for each entry.
        if (rng.next() & 1) {
            it = map_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    // If we did not remove enough on the first pass (unlikely but possible),
    // do a second pass removing unconditionally until we hit the target.
    for (auto it = map_.begin(); it != map_.end() && removed < target_removals; ) {
        it = map_.erase(it);
        ++removed;
    }
}

// ---------------------------------------------------------------------------
// get_sig_cache  --  singleton accessor
// ---------------------------------------------------------------------------

SigCache& get_sig_cache() {
    static SigCache instance(SigCache::DEFAULT_MAX_SIZE);
    return instance;
}

}  // namespace consensus
