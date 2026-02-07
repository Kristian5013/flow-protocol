// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempool/orphan.h"

#include "core/logging.h"
#include "core/time.h"
#include "core/types.h"
#include "primitives/outpoint.h"
#include "primitives/transaction.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// add
// ---------------------------------------------------------------------------

bool OrphanPool::add(const primitives::Transaction& tx, uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    core::uint256 txid = tx.txid();

    // Reject if already present.
    if (orphans_.count(txid) > 0) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "orphan pool: tx " + txid.to_hex() + " already exists");
        return false;
    }

    // Reject if too large.
    size_t tx_size = tx.total_size();
    if (tx_size > MAX_ORPHAN_TX_SIZE) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "orphan pool: tx " + txid.to_hex() + " too large ("
            + std::to_string(tx_size) + " > "
            + std::to_string(MAX_ORPHAN_TX_SIZE) + ")");
        return false;
    }

    // Reject coinbase transactions (they can never become valid orphans).
    if (tx.is_coinbase()) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "orphan pool: rejecting coinbase tx " + txid.to_hex());
        return false;
    }

    // Reject transactions with no inputs (invalid structure).
    if (tx.vin().empty()) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "orphan pool: rejecting tx " + txid.to_hex()
            + " with no inputs");
        return false;
    }

    // Reject transactions with no outputs (invalid structure).
    if (tx.vout().empty()) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "orphan pool: rejecting tx " + txid.to_hex()
            + " with no outputs");
        return false;
    }

    // Per-peer limit: don't let a single peer fill the orphan pool.
    // Maximum 5 orphans per peer as a DoS mitigation.
    constexpr size_t MAX_ORPHANS_PER_PEER = 5;
    {
        auto pit = peer_orphan_count_.find(peer_id);
        if (pit != peer_orphan_count_.end()
            && pit->second >= MAX_ORPHANS_PER_PEER) {
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "orphan pool: rejecting tx " + txid.to_hex()
                + " from peer " + std::to_string(peer_id)
                + " (per-peer limit " + std::to_string(MAX_ORPHANS_PER_PEER)
                + " reached)");
            return false;
        }
    }

    // Build the entry.
    OrphanEntry entry;
    entry.tx          = tx;
    entry.txid        = txid;
    entry.peer_id     = peer_id;
    entry.expiry_time = core::get_time() + ORPHAN_EXPIRY;
    entry.size        = tx_size;

    // Index by outpoints spent.
    add_to_outpoint_index(entry);

    // Track per-peer count.
    peer_orphan_count_[peer_id]++;

    // Insert into main map.
    orphans_.emplace(txid, std::move(entry));

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "orphan pool: added tx " + txid.to_hex()
        + " from peer " + std::to_string(peer_id)
        + " (pool size: " + std::to_string(orphans_.size()) + ")");

    return true;
}

// ---------------------------------------------------------------------------
// erase
// ---------------------------------------------------------------------------

void OrphanPool::erase(const core::uint256& txid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = orphans_.find(txid);
    if (it == orphans_.end()) {
        return;
    }

    // Remove from outpoint index.
    remove_from_outpoint_index(it->second);

    // Decrement per-peer count.
    uint64_t pid = it->second.peer_id;
    auto pit = peer_orphan_count_.find(pid);
    if (pit != peer_orphan_count_.end()) {
        if (pit->second <= 1) {
            peer_orphan_count_.erase(pit);
        } else {
            pit->second--;
        }
    }

    orphans_.erase(it);

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "orphan pool: erased tx " + txid.to_hex()
        + " (pool size: " + std::to_string(orphans_.size()) + ")");
}

// ---------------------------------------------------------------------------
// erase_for_peer
// ---------------------------------------------------------------------------

void OrphanPool::erase_for_peer(uint64_t peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Collect txids to remove first (cannot erase while iterating).
    std::vector<core::uint256> to_remove;
    to_remove.reserve(orphans_.size());

    for (const auto& [txid, entry] : orphans_) {
        if (entry.peer_id == peer_id) {
            to_remove.push_back(txid);
        }
    }

    for (const auto& txid : to_remove) {
        auto it = orphans_.find(txid);
        if (it != orphans_.end()) {
            remove_from_outpoint_index(it->second);
            orphans_.erase(it);
        }
    }

    peer_orphan_count_.erase(peer_id);

    if (!to_remove.empty()) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "orphan pool: erased " + std::to_string(to_remove.size())
            + " orphans from peer " + std::to_string(peer_id)
            + " (pool size: " + std::to_string(orphans_.size()) + ")");
    }
}

// ---------------------------------------------------------------------------
// limit_size
// ---------------------------------------------------------------------------

void OrphanPool::limit_size() {
    std::lock_guard<std::mutex> lock(mutex_);

    // First, expire old entries.
    int64_t now = core::get_time();
    {
        std::vector<core::uint256> expired;
        for (const auto& [txid, entry] : orphans_) {
            if (entry.expiry_time <= now) {
                expired.push_back(txid);
            }
        }
        for (const auto& txid : expired) {
            auto it = orphans_.find(txid);
            if (it != orphans_.end()) {
                remove_from_outpoint_index(it->second);
                uint64_t pid = it->second.peer_id;
                orphans_.erase(it);
                auto pit = peer_orphan_count_.find(pid);
                if (pit != peer_orphan_count_.end()) {
                    if (pit->second <= 1) {
                        peer_orphan_count_.erase(pit);
                    } else {
                        pit->second--;
                    }
                }
            }
        }
        if (!expired.empty()) {
            LOG_DEBUG(core::LogCategory::MEMPOOL,
                "orphan pool: expired " + std::to_string(expired.size())
                + " orphans");
        }
    }

    // Then evict random entries until we are within the limit.
    // Using the iteration order of unordered_map which is effectively random.
    size_t evicted = 0;
    while (orphans_.size() > MAX_ORPHAN_TRANSACTIONS) {
        auto it = orphans_.begin();
        if (it == orphans_.end()) break;

        remove_from_outpoint_index(it->second);
        uint64_t pid = it->second.peer_id;
        orphans_.erase(it);

        auto pit = peer_orphan_count_.find(pid);
        if (pit != peer_orphan_count_.end()) {
            if (pit->second <= 1) {
                peer_orphan_count_.erase(pit);
            } else {
                pit->second--;
            }
        }
        ++evicted;
    }

    if (evicted > 0) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "orphan pool: evicted " + std::to_string(evicted)
            + " orphans to enforce size limit (pool size: "
            + std::to_string(orphans_.size()) + ")");
    }
}

// ---------------------------------------------------------------------------
// expire
// ---------------------------------------------------------------------------

void OrphanPool::expire(int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<core::uint256> expired;
    for (const auto& [txid, entry] : orphans_) {
        if (entry.expiry_time <= now) {
            expired.push_back(txid);
        }
    }

    for (const auto& txid : expired) {
        auto it = orphans_.find(txid);
        if (it != orphans_.end()) {
            remove_from_outpoint_index(it->second);
            uint64_t pid = it->second.peer_id;
            orphans_.erase(it);

            auto pit = peer_orphan_count_.find(pid);
            if (pit != peer_orphan_count_.end()) {
                if (pit->second <= 1) {
                    peer_orphan_count_.erase(pit);
                } else {
                    pit->second--;
                }
            }
        }
    }

    if (!expired.empty()) {
        LOG_INFO(core::LogCategory::MEMPOOL,
            "orphan pool: expired " + std::to_string(expired.size())
            + " orphans (pool size: " + std::to_string(orphans_.size())
            + ")");
    }
}

// ---------------------------------------------------------------------------
// clear
// ---------------------------------------------------------------------------

void OrphanPool::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    orphans_.clear();
    outpoint_index_.clear();
    peer_orphan_count_.clear();
}

// ---------------------------------------------------------------------------
// exists
// ---------------------------------------------------------------------------

bool OrphanPool::exists(const core::uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return orphans_.count(txid) > 0;
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

const OrphanEntry* OrphanPool::get(const core::uint256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = orphans_.find(txid);
    if (it == orphans_.end()) return nullptr;
    return &it->second;
}

// ---------------------------------------------------------------------------
// get_children
// ---------------------------------------------------------------------------

std::vector<primitives::Transaction>
OrphanPool::get_children(const primitives::OutPoint& outpoint) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<primitives::Transaction> result;

    auto it = outpoint_index_.find(outpoint);
    if (it == outpoint_index_.end()) {
        return result;
    }

    result.reserve(it->second.size());
    for (const auto& txid : it->second) {
        auto oit = orphans_.find(txid);
        if (oit != orphans_.end()) {
            result.push_back(oit->second.tx);
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// get_children_of_tx
// ---------------------------------------------------------------------------

std::vector<primitives::Transaction>
OrphanPool::get_children_of_tx(const core::uint256& parent_txid,
                               uint32_t num_outputs) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Use a set to deduplicate (an orphan may spend multiple outputs
    // from the same parent).
    struct Uint256Hash {
        std::size_t operator()(const core::uint256& v) const noexcept {
            return std::hash<core::uint256>{}(v);
        }
    };
    std::unordered_set<core::uint256, Uint256Hash> seen;
    std::vector<primitives::Transaction> result;

    for (uint32_t i = 0; i < num_outputs; ++i) {
        primitives::OutPoint op(parent_txid, i);
        auto it = outpoint_index_.find(op);
        if (it == outpoint_index_.end()) continue;

        for (const auto& txid : it->second) {
            if (seen.insert(txid).second) {
                auto oit = orphans_.find(txid);
                if (oit != orphans_.end()) {
                    result.push_back(oit->second.tx);
                }
            }
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// size / memory_usage
// ---------------------------------------------------------------------------

size_t OrphanPool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return orphans_.size();
}

size_t OrphanPool::memory_usage() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t usage = 0;

    // Each orphan entry: fixed struct overhead + transaction data.
    for (const auto& [txid, entry] : orphans_) {
        usage += sizeof(OrphanEntry);
        usage += entry.size; // serialized tx size as proxy for heap usage

        // Input/output heap allocations.
        for (const auto& input : entry.tx.vin()) {
            usage += input.script_sig.capacity();
            for (const auto& wit : input.witness) {
                usage += wit.capacity();
            }
        }
        for (const auto& output : entry.tx.vout()) {
            usage += output.script_pubkey.capacity();
        }
    }

    // Outpoint index overhead.
    usage += outpoint_index_.size()
           * (sizeof(primitives::OutPoint) + sizeof(Uint256Set));

    return usage;
}

// ---------------------------------------------------------------------------
// get_all_txids
// ---------------------------------------------------------------------------

std::vector<core::uint256> OrphanPool::get_all_txids() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<core::uint256> result;
    result.reserve(orphans_.size());
    for (const auto& [txid, entry] : orphans_) {
        result.push_back(txid);
    }
    return result;
}

// ---------------------------------------------------------------------------
// count_for_peer
// ---------------------------------------------------------------------------

size_t OrphanPool::count_for_peer(uint64_t peer_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peer_orphan_count_.find(peer_id);
    if (it == peer_orphan_count_.end()) return 0;
    return it->second;
}

// ---------------------------------------------------------------------------
// Internal: outpoint index management
// ---------------------------------------------------------------------------

void OrphanPool::add_to_outpoint_index(const OrphanEntry& entry) {
    for (const auto& input : entry.tx.vin()) {
        outpoint_index_[input.prevout].insert(entry.txid);
    }
}

void OrphanPool::remove_from_outpoint_index(const OrphanEntry& entry) {
    for (const auto& input : entry.tx.vin()) {
        auto it = outpoint_index_.find(input.prevout);
        if (it != outpoint_index_.end()) {
            it->second.erase(entry.txid);
            if (it->second.empty()) {
                outpoint_index_.erase(it);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// get_missing_outpoints
// ---------------------------------------------------------------------------

std::vector<primitives::OutPoint>
OrphanPool::get_missing_outpoints() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<primitives::OutPoint> missing;
    missing.reserve(outpoint_index_.size());

    for (const auto& [outpoint, txids] : outpoint_index_) {
        if (!txids.empty()) {
            missing.push_back(outpoint);
        }
    }

    return missing;
}

// ---------------------------------------------------------------------------
// outpoint_index_size
// ---------------------------------------------------------------------------

size_t OrphanPool::outpoint_index_size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return outpoint_index_.size();
}

// ---------------------------------------------------------------------------
// has_outpoint
// ---------------------------------------------------------------------------

bool OrphanPool::has_outpoint(const primitives::OutPoint& outpoint) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = outpoint_index_.find(outpoint);
    return it != outpoint_index_.end() && !it->second.empty();
}

// ---------------------------------------------------------------------------
// get_peer_ids
// ---------------------------------------------------------------------------

std::vector<uint64_t> OrphanPool::get_peer_ids() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<uint64_t> peers;
    peers.reserve(peer_orphan_count_.size());
    for (const auto& [peer_id, count] : peer_orphan_count_) {
        if (count > 0) {
            peers.push_back(peer_id);
        }
    }
    return peers;
}

// ---------------------------------------------------------------------------
// dump
// ---------------------------------------------------------------------------

std::string OrphanPool::dump() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string result;
    result += "OrphanPool: " + std::to_string(orphans_.size())
            + " orphans, " + std::to_string(outpoint_index_.size())
            + " indexed outpoints\n";

    for (const auto& [txid, entry] : orphans_) {
        result += "  " + txid.to_hex().substr(0, 16) + "..."
                + " peer=" + std::to_string(entry.peer_id)
                + " size=" + std::to_string(entry.size)
                + " inputs=" + std::to_string(entry.tx.vin().size())
                + " outputs=" + std::to_string(entry.tx.vout().size())
                + " expiry=" + std::to_string(entry.expiry_time)
                + "\n";
    }

    result += "Per-peer counts:\n";
    for (const auto& [peer_id, count] : peer_orphan_count_) {
        result += "  peer " + std::to_string(peer_id)
                + ": " + std::to_string(count) + " orphans\n";
    }

    return result;
}

// ---------------------------------------------------------------------------
// OrphanStats::to_string
// ---------------------------------------------------------------------------

std::string OrphanPool::OrphanStats::to_string() const {
    std::string result;

    result += "OrphanPool Statistics:\n";
    result += "  count:            " + std::to_string(count) + "\n";
    result += "  total_size:       " + std::to_string(total_size) + " bytes\n";
    result += "  indexed_outpoints:" + std::to_string(indexed_outpoints) + "\n";
    result += "  peer_count:       " + std::to_string(peer_count) + "\n";
    result += "  max_per_peer:     " + std::to_string(max_per_peer) + "\n";
    result += "  avg_age:          " + std::to_string(avg_age) + " seconds\n";
    result += "  expired_count:    " + std::to_string(expired_count) + "\n";
    result += "  total_inputs:     " + std::to_string(total_inputs) + "\n";
    result += "  total_outputs:    " + std::to_string(total_outputs) + "\n";
    result += "  memory_bytes:     " + std::to_string(memory_bytes) + "\n";

    return result;
}

// ---------------------------------------------------------------------------
// compute_stats
// ---------------------------------------------------------------------------

OrphanPool::OrphanStats OrphanPool::compute_stats(int64_t now) const {
    std::lock_guard<std::mutex> lock(mutex_);

    OrphanStats stats;
    stats.count = orphans_.size();
    stats.indexed_outpoints = outpoint_index_.size();
    stats.peer_count = peer_orphan_count_.size();

    // Compute per-peer max.
    for (const auto& [peer_id, cnt] : peer_orphan_count_) {
        if (cnt > stats.max_per_peer) {
            stats.max_per_peer = cnt;
        }
    }

    // Aggregate entry-level stats.
    int64_t total_age = 0;
    for (const auto& [txid, entry] : orphans_) {
        stats.total_size += entry.size;
        stats.total_inputs += entry.tx.vin().size();
        stats.total_outputs += entry.tx.vout().size();

        // Compute age: time since entry was added.
        // expiry_time = creation_time + ORPHAN_EXPIRY
        // so creation_time = expiry_time - ORPHAN_EXPIRY
        int64_t creation_time = entry.expiry_time - ORPHAN_EXPIRY;
        int64_t age = now - creation_time;
        if (age < 0) age = 0;
        total_age += age;

        if (entry.expiry_time <= now) {
            stats.expired_count++;
        }
    }

    if (stats.count > 0) {
        stats.avg_age = static_cast<double>(total_age)
                      / static_cast<double>(stats.count);
    }

    // Estimate memory usage (reuse the memory_usage() computation).
    size_t usage = 0;
    for (const auto& [txid, entry] : orphans_) {
        usage += sizeof(OrphanEntry);
        usage += entry.size;
        for (const auto& input : entry.tx.vin()) {
            usage += input.script_sig.capacity();
            for (const auto& wit : input.witness) {
                usage += wit.capacity();
            }
        }
        for (const auto& output : entry.tx.vout()) {
            usage += output.script_pubkey.capacity();
        }
    }
    usage += outpoint_index_.size()
           * (sizeof(primitives::OutPoint) + sizeof(Uint256Set));
    stats.memory_bytes = usage;

    return stats;
}

// ---------------------------------------------------------------------------
// oldest_orphan
// ---------------------------------------------------------------------------

const OrphanEntry* OrphanPool::oldest_orphan() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (orphans_.empty()) return nullptr;

    const OrphanEntry* oldest = nullptr;
    for (const auto& [txid, entry] : orphans_) {
        if (oldest == nullptr || entry.expiry_time < oldest->expiry_time) {
            oldest = &entry;
        }
    }
    return oldest;
}

// ---------------------------------------------------------------------------
// newest_orphan
// ---------------------------------------------------------------------------

const OrphanEntry* OrphanPool::newest_orphan() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (orphans_.empty()) return nullptr;

    const OrphanEntry* newest = nullptr;
    for (const auto& [txid, entry] : orphans_) {
        if (newest == nullptr || entry.expiry_time > newest->expiry_time) {
            newest = &entry;
        }
    }
    return newest;
}

// ---------------------------------------------------------------------------
// largest_orphan
// ---------------------------------------------------------------------------

const OrphanEntry* OrphanPool::largest_orphan() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (orphans_.empty()) return nullptr;

    const OrphanEntry* largest = nullptr;
    for (const auto& [txid, entry] : orphans_) {
        if (largest == nullptr || entry.size > largest->size) {
            largest = &entry;
        }
    }
    return largest;
}

// ---------------------------------------------------------------------------
// has_children_of
// ---------------------------------------------------------------------------

bool OrphanPool::has_children_of(const core::uint256& parent_txid,
                                  uint32_t num_outputs) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (uint32_t i = 0; i < num_outputs; ++i) {
        primitives::OutPoint op(parent_txid, i);
        auto it = outpoint_index_.find(op);
        if (it != outpoint_index_.end() && !it->second.empty()) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// waiting_parent_count
// ---------------------------------------------------------------------------

size_t OrphanPool::waiting_parent_count() const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Count the number of unique parent txids referenced by orphan inputs.
    struct Uint256HashLocal {
        std::size_t operator()(const core::uint256& v) const noexcept {
            return std::hash<core::uint256>{}(v);
        }
    };
    std::unordered_set<core::uint256, Uint256HashLocal> parent_txids;

    for (const auto& [outpoint, txids] : outpoint_index_) {
        if (!txids.empty()) {
            parent_txids.insert(outpoint.txid);
        }
    }

    return parent_txids.size();
}

// ===========================================================================
// Orphan pool design notes
// ===========================================================================
//
// The orphan pool serves as a temporary holding area for transactions whose
// inputs are not yet available (the parent transaction has not been seen).
// This is common during the initial block download (IBD) and during normal
// operation when transactions arrive out of order over the P2P network.
//
// Key design decisions:
//
// 1. SIZE LIMIT
//    The pool is limited to MAX_ORPHAN_TRANSACTIONS (100) entries. This
//    prevents memory exhaustion attacks where a peer floods us with orphan
//    transactions. When the limit is exceeded, entries are evicted in
//    iteration order (which is effectively random for unordered_map).
//
// 2. TIME LIMIT
//    Orphans expire after ORPHAN_EXPIRY (20 minutes). If a parent has not
//    arrived within this window, the orphan is likely never going to be
//    valid. Keeping it longer would waste memory.
//
// 3. SIZE LIMIT PER ORPHAN
//    Individual orphans larger than MAX_ORPHAN_TX_SIZE (100 KB) are
//    rejected. This prevents a single large orphan from consuming a
//    disproportionate share of the pool.
//
// 4. PER-PEER TRACKING
//    Each orphan records which peer sent it. This allows us to:
//      - Evict all orphans from a misbehaving peer (erase_for_peer).
//      - Track per-peer orphan counts for DoS scoring.
//
// 5. OUTPOINT INDEX
//    A secondary index maps outpoints to the set of orphan txids that
//    spend them. When a parent transaction arrives, we can efficiently
//    find all orphans that may now be valid using get_children() or
//    get_children_of_tx().
//
// 6. THREAD SAFETY
//    The orphan pool has its own mutex, independent of the mempool mutex.
//    This allows concurrent access to the orphan pool without blocking
//    mempool reads. The orphan pool never calls back into the mempool,
//    preventing deadlock.
//

} // namespace mempool
