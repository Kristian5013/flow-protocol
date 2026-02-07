// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempool/entry.h"

#include "core/logging.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"
#include "primitives/txin.h"
#include "primitives/txout.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace mempool {

// ---------------------------------------------------------------------------
// Fee rate helpers
// ---------------------------------------------------------------------------

double MempoolEntry::fee_rate() const {
    if (vsize == 0) return 0.0;
    return static_cast<double>(fee.value()) / static_cast<double>(vsize);
}

double MempoolEntry::ancestor_fee_rate() const {
    if (ancestor_size == 0) return 0.0;
    return static_cast<double>(ancestor_fees.value())
         / static_cast<double>(ancestor_size);
}

double MempoolEntry::descendant_fee_rate() const {
    if (descendant_size == 0) return 0.0;
    return static_cast<double>(descendant_fees.value())
         / static_cast<double>(descendant_size);
}

int64_t MempoolEntry::fee_rate_per_kvb() const {
    if (vsize == 0) return 0;
    // fee_per_kvb = fee * 1000 / vsize, rounded up to ensure that
    // a transaction always meets the rate it claims.
    int64_t f = fee.value();
    return (f * 1000 + static_cast<int64_t>(vsize) - 1)
         / static_cast<int64_t>(vsize);
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

double MempoolEntry::mining_score() const {
    // The mining score is the ancestor fee rate. The miner picks the
    // transaction with the highest ancestor fee rate because including
    // that transaction (along with its in-mempool ancestors) yields the
    // best marginal revenue per virtual byte.
    return ancestor_fee_rate();
}

double MempoolEntry::eviction_score() const {
    // The eviction score is the descendant fee rate. When the mempool is
    // full, we evict the transaction with the lowest descendant fee rate
    // because removing it (along with its descendants) frees the most
    // space for the least fee loss.
    return descendant_fee_rate();
}

bool MempoolEntry::is_better_for_mining(const MempoolEntry& other) const {
    double our_score   = mining_score();
    double their_score = other.mining_score();
    if (our_score != their_score) {
        return our_score > their_score;
    }
    // Tie-break by ancestor size (prefer smaller packages so more
    // transactions can fit in the block).
    if (ancestor_size != other.ancestor_size) {
        return ancestor_size < other.ancestor_size;
    }
    // Further tie-break by time (prefer older transactions for fairness).
    return time < other.time;
}

bool MempoolEntry::should_evict_before(const MempoolEntry& other) const {
    double our_score   = eviction_score();
    double their_score = other.eviction_score();
    if (our_score != their_score) {
        return our_score < their_score;
    }
    // Tie-break by descendant size (prefer evicting larger packages first
    // to free more space).
    if (descendant_size != other.descendant_size) {
        return descendant_size > other.descendant_size;
    }
    // Further tie-break by time (evict newer transactions first, keeping
    // older ones which have been waiting longer).
    return time > other.time;
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

int64_t MempoolEntry::age(int64_t now) const {
    if (now <= time) return 0;
    return now - time;
}

int32_t MempoolEntry::blocks_in_pool(int32_t current_height) const {
    if (current_height <= height) return 0;
    return current_height - height;
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

bool MempoolEntry::is_coinbase() const {
    return tx.is_coinbase();
}

bool MempoolEntry::has_witness() const {
    return tx.has_witness();
}

size_t MempoolEntry::weight() const {
    return tx.weight();
}

size_t MempoolEntry::input_count() const {
    return tx.vin().size();
}

size_t MempoolEntry::output_count() const {
    return tx.vout().size();
}

primitives::Amount MempoolEntry::total_output_value() const {
    int64_t total = 0;
    for (const auto& output : tx.vout()) {
        total += output.amount.value();
    }
    return primitives::Amount{total};
}

// ---------------------------------------------------------------------------
// Dynamic memory usage estimation
// ---------------------------------------------------------------------------

size_t MempoolEntry::dynamic_memory_usage() const {
    // We estimate the heap allocations made by this entry's transaction.
    // The MempoolEntry struct itself is fixed-size and already accounted
    // for by the container that holds it (the unordered_map in Mempool).
    size_t usage = 0;

    // --- Transaction inputs ---
    // The vin vector itself allocates capacity * sizeof(TxInput) on the heap.
    usage += tx.vin().capacity() * sizeof(primitives::TxInput);

    for (const auto& input : tx.vin()) {
        // Each input's scriptSig is a separate heap allocation.
        usage += input.script_sig.capacity();

        // Each input's witness is a vector of vectors.
        // First, the outer vector allocation.
        usage += input.witness.capacity() * sizeof(std::vector<uint8_t>);

        // Then, each inner witness item's heap allocation.
        for (const auto& item : input.witness) {
            usage += item.capacity();
        }
    }

    // --- Transaction outputs ---
    // The vout vector allocates capacity * sizeof(TxOutput) on the heap.
    usage += tx.vout().capacity() * sizeof(primitives::TxOutput);

    for (const auto& output : tx.vout()) {
        // Each output's scriptPubKey is a separate heap allocation.
        usage += output.script_pubkey.capacity();
    }

    // The txid and wtxid fields are 32-byte fixed arrays (Blob<32>),
    // stored inline in the MempoolEntry. No heap allocation.

    // The Amount fields are trivial (int64_t), no heap allocation.

    return usage;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

MempoolEntry MempoolEntry::from_tx(const primitives::Transaction& tx,
                                   primitives::Amount fee,
                                   int32_t height,
                                   int64_t time) {
    MempoolEntry entry;

    // Copy the transaction and cache its hashes.
    entry.tx     = tx;
    entry.txid   = tx.txid();
    entry.wtxid  = tx.wtxid();

    // Store the fee and size metrics.
    entry.fee    = fee;
    entry.size   = tx.total_size();
    entry.vsize  = tx.vsize();

    // Store the contextual metadata.
    entry.time   = time;
    entry.height = height;

    // Initialize ancestor/descendant state to cover only self.
    // These will be updated by the AncestorTracker after the entry is
    // placed in the mempool.
    entry.ancestor_count    = 1;
    entry.ancestor_size     = entry.vsize;
    entry.ancestor_fees     = fee;

    entry.descendant_count  = 1;
    entry.descendant_size   = entry.vsize;
    entry.descendant_fees   = fee;

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "MempoolEntry::from_tx: created entry for "
        + entry.txid.to_hex()
        + " fee=" + std::to_string(fee.value())
        + " vsize=" + std::to_string(entry.vsize)
        + " height=" + std::to_string(height));

    return entry;
}

// ---------------------------------------------------------------------------
// Human-readable summary
// ---------------------------------------------------------------------------

std::string MempoolEntry::to_string() const {
    std::ostringstream oss;
    oss << "txid=" << txid.to_hex()
        << " fee=" << fee.value()
        << " vsize=" << vsize
        << " feerate=";

    // Format fee rate with two decimal places.
    double rate = fee_rate();
    oss << std::fixed << std::setprecision(2) << rate << " sat/vB"
        << " ancestors=" << ancestor_count
        << " descendants=" << descendant_count;

    return oss.str();
}

std::string MempoolEntry::to_debug_string() const {
    std::ostringstream oss;

    oss << "MempoolEntry {\n"
        << "  txid:    " << txid.to_hex() << "\n"
        << "  wtxid:   " << wtxid.to_hex() << "\n"
        << "  fee:     " << fee.value() << " sat\n"
        << "  size:    " << size << " bytes\n"
        << "  vsize:   " << vsize << " vB\n"
        << "  weight:  " << tx.weight() << " WU\n"
        << "  time:    " << time << "\n"
        << "  height:  " << height << "\n";

    oss << std::fixed << std::setprecision(4);
    oss << "  fee_rate:            " << fee_rate() << " sat/vB\n"
        << "  fee_rate_per_kvb:    " << fee_rate_per_kvb() << " sat/kvB\n"
        << "  ancestor_fee_rate:   " << ancestor_fee_rate() << " sat/vB\n"
        << "  descendant_fee_rate: " << descendant_fee_rate() << " sat/vB\n"
        << "  mining_score:        " << mining_score() << "\n"
        << "  eviction_score:      " << eviction_score() << "\n";

    oss << "  ancestors:   count=" << ancestor_count
        << " size=" << ancestor_size << " vB"
        << " fees=" << ancestor_fees.value() << " sat\n"
        << "  descendants: count=" << descendant_count
        << " size=" << descendant_size << " vB"
        << " fees=" << descendant_fees.value() << " sat\n";

    oss << "  inputs:  " << tx.vin().size() << "\n"
        << "  outputs: " << tx.vout().size() << "\n"
        << "  coinbase: " << (tx.is_coinbase() ? "yes" : "no") << "\n"
        << "  witness:  " << (tx.has_witness() ? "yes" : "no") << "\n";

    // Output value summary.
    int64_t total_out = 0;
    for (const auto& output : tx.vout()) {
        total_out += output.amount.value();
    }
    oss << "  total_output_value: " << total_out << " sat\n";

    oss << "  dynamic_memory_usage: " << dynamic_memory_usage() << " bytes\n"
        << "}\n";

    return oss.str();
}

// ---------------------------------------------------------------------------
// Median fee rate computation
// ---------------------------------------------------------------------------

double compute_median_fee_rate(std::vector<MempoolEntry> entries) {
    if (entries.empty()) return 0.0;

    // Sort by fee rate.
    std::sort(entries.begin(), entries.end(),
        [](const MempoolEntry& a, const MempoolEntry& b) {
            return a.fee_rate() < b.fee_rate();
        });

    size_t n = entries.size();
    if (n % 2 == 1) {
        return entries[n / 2].fee_rate();
    }

    // Even number of entries: average of the two middle values.
    double mid1 = entries[n / 2 - 1].fee_rate();
    double mid2 = entries[n / 2].fee_rate();
    return (mid1 + mid2) / 2.0;
}

// ---------------------------------------------------------------------------
// Fee rate percentile computation
// ---------------------------------------------------------------------------

double compute_fee_rate_percentile(std::vector<MempoolEntry> entries,
                                   int percentile) {
    if (entries.empty()) return 0.0;
    if (percentile <= 0) percentile = 0;
    if (percentile >= 100) percentile = 100;

    // Sort by fee rate.
    std::sort(entries.begin(), entries.end(),
        [](const MempoolEntry& a, const MempoolEntry& b) {
            return a.fee_rate() < b.fee_rate();
        });

    // Compute the index for the given percentile using nearest-rank method.
    // index = ceil(percentile / 100.0 * n) - 1
    size_t n = entries.size();
    size_t index = static_cast<size_t>(
        static_cast<double>(percentile) / 100.0
        * static_cast<double>(n) + 0.5);

    if (index == 0) index = 1;
    if (index > n) index = n;

    return entries[index - 1].fee_rate();
}

// ===========================================================================
// MempoolEntry design notes
// ===========================================================================
//
// ANCESTOR FEE RATE MINING
// ------------------------
// The MempoolEntry's mining_score() returns the ancestor fee rate, which
// is the key metric used by the block assembly algorithm. The idea is:
//
// To include a transaction in a block, the miner must also include all
// of its unconfirmed ancestors. The "effective" fee rate of including
// the transaction is therefore:
//
//   effective_rate = sum(ancestor_fees) / sum(ancestor_vsizes)
//
// The miner greedily selects the transaction with the highest effective
// rate, includes it and all its ancestors, then updates the remaining
// entries and repeats. This is the ancestor-feerate mining algorithm
// originally described by Pieter Wuille and implemented in Bitcoin Core.
//
// After selecting an entry, its ancestors' descendant counts decrease
// (because the selected entry is no longer a descendant). This may
// change the mining scores of other entries, so the algorithm must
// recompute scores after each selection.
//
// DESCENDANT FEE RATE EVICTION
// ----------------------------
// The eviction_score() returns the descendant fee rate, used when the
// mempool is full and must shed transactions. The reasoning is:
//
// Evicting a transaction also effectively evicts all its descendants
// (since they can no longer confirm without their parent). The "damage"
// of evicting a transaction is measured by the total fee that would be
// lost per virtual byte freed:
//
//   damage_rate = sum(descendant_fees) / sum(descendant_vsizes)
//
// The miner wants to minimize damage, so it evicts the transaction
// with the lowest descendant fee rate first.
//
// TIE-BREAKING
// ------------
// When two entries have the same score, we use deterministic tie-breaking
// to ensure consistent behavior across runs and between nodes:
//
//   1. For mining: prefer smaller ancestor packages (more room in block).
//   2. For eviction: prefer evicting larger descendant packages (frees
//      more space per eviction decision).
//   3. Final tie-break: use entry time (older = higher priority for
//      mining, newer = evicted first for fairness).
//
// COMPARISON FUNCTORS
// -------------------
// The comparison functors (CompareByFeeRate, CompareByAncestorFeeRate,
// etc.) are designed for use with std::priority_queue, std::set, and
// std::sort. They follow the "strict weak ordering" requirement:
//
//   - CompareByFeeRate: descending by individual fee rate.
//   - CompareByAncestorFeeRate: descending by ancestor fee rate, with
//     tie-breaking by ancestor size (ascending).
//   - CompareByDescendantFeeRate: ascending by descendant fee rate, with
//     tie-breaking by descendant size (descending).
//   - CompareByTime: ascending by entry time (oldest first).
//   - CompareBySize: descending by total serialized size.
//   - CompareByMiningScore: uses is_better_for_mining() with full
//     tie-breaking.
//   - CompareByEvictionPriority: uses should_evict_before() with full
//     tie-breaking.
//

} // namespace mempool
