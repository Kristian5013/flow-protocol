/**
 * FTC Mempool Implementation
 * Full transaction pool with fee-based ordering and ancestor tracking
 */

#include "chain/mempool.h"
#include "chain/chain.h"
#include "util/logging.h"
#include <algorithm>
#include <queue>

namespace ftc {
namespace chain {

Mempool::Mempool() : Mempool(Config{}) {}

Mempool::Mempool(const Config& config) : config_(config) {}

Mempool::~Mempool() {
    clear();
}

MempoolReject Mempool::addTransaction(const Transaction& tx, int32_t current_height) {
    crypto::Hash256 txid = tx.getTxId();

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if already in mempool
    if (entries_.count(txid) > 0) {
        return MempoolReject::ALREADY_IN_MEMPOOL;
    }

    // Check transaction size
    uint64_t tx_size = tx.getSize();
    if (tx_size > config_.max_tx_size) {
        LOG_DEBUG("Transaction {} too large: {} > {}",
                  crypto::Keccak256::toHex(txid).substr(0, 16), tx_size, config_.max_tx_size);
        return MempoolReject::TOO_LARGE;
    }

    // Check inputs and calculate fee
    uint64_t fee = 0;
    std::string error;
    if (!checkInputs(tx, current_height, fee, error)) {
        LOG_DEBUG("Transaction {} rejected: {}", crypto::Keccak256::toHex(txid).substr(0, 16), error);

        if (error == "missing inputs") return MempoolReject::MISSING_INPUTS;
        if (error == "double spend") return MempoolReject::DOUBLE_SPEND;
        if (error == "immature coinbase") return MempoolReject::IMMATURE_COINBASE;
        if (error == "negative fee") return MempoolReject::NEGATIVE_FEE;

        return MempoolReject::SCRIPT_ERROR;
    }

    // Calculate fee rate
    double fee_rate = static_cast<double>(fee) / tx_size;

    // Check minimum fee
    double min_fee_rate = static_cast<double>(config_.min_relay_fee) / 1000.0;
    if (fee_rate < min_fee_rate) {
        LOG_DEBUG("Transaction {} fee too low: {} < {}",
                  crypto::Keccak256::toHex(txid).substr(0, 16), fee_rate, min_fee_rate);
        return MempoolReject::INSUFFICIENT_FEE;
    }

    // Calculate ancestors and descendants
    std::set<crypto::Hash256> ancestors;
    std::set<crypto::Hash256> descendants;

    // Find parent transactions (transactions spending our inputs)
    for (const auto& input : tx.inputs) {
        Outpoint outpoint{input.prevout.txid, input.prevout.index};

        // Check if output created by another mempool tx
        auto created_it = created_outputs_.find(outpoint);
        if (created_it != created_outputs_.end()) {
            ancestors.insert(created_it->second);

            // Recursively add ancestors of parent
            auto parent_ancestors = calculateAncestors(created_it->second, config_.max_ancestors);
            ancestors.insert(parent_ancestors.begin(), parent_ancestors.end());
        }
    }

    // Check ancestor limits
    if (ancestors.size() > config_.max_ancestors) {
        return MempoolReject::ANCESTOR_LIMIT;
    }

    uint64_t ancestor_size = tx_size;
    uint64_t ancestor_fee = fee;
    for (const auto& ancestor : ancestors) {
        auto it = entries_.find(ancestor);
        if (it != entries_.end()) {
            ancestor_size += it->second.size;
            ancestor_fee += it->second.fee;
        }
    }

    if (ancestor_size > config_.max_ancestor_size) {
        return MempoolReject::ANCESTOR_LIMIT;
    }

    // Check if mempool is full
    if (total_size_ + tx_size > config_.max_size) {
        // Try to make room by evicting low-fee transactions
        trimToSize(config_.max_size - tx_size);

        if (total_size_ + tx_size > config_.max_size) {
            return MempoolReject::MEMPOOL_FULL;
        }
    }

    // Create entry
    MempoolEntry entry;
    entry.tx = tx;
    entry.txid = txid;
    entry.fee = fee;
    entry.size = tx_size;
    entry.fee_rate = fee_rate;
    entry.time_added = std::chrono::steady_clock::now();
    entry.height_added = current_height;
    entry.ancestor_count = ancestors.size();
    entry.ancestor_size = ancestor_size;
    entry.ancestor_fee = ancestor_fee;

    // Add to indices
    entries_[txid] = std::move(entry);
    by_fee_rate_.insert({fee_rate, txid});
    total_size_ += tx_size;

    // Track spent outputs
    for (const auto& input : tx.inputs) {
        Outpoint outpoint{input.prevout.txid, input.prevout.index};
        spent_outputs_[outpoint] = txid;
    }

    // Track created outputs
    for (uint32_t i = 0; i < tx.outputs.size(); i++) {
        Outpoint outpoint{txid, i};
        created_outputs_[outpoint] = txid;
    }

    // Update parent/child relationships
    for (const auto& ancestor : ancestors) {
        parents_[txid].insert(ancestor);
        children_[ancestor].insert(txid);
    }

    // Update descendant counts for ancestors
    for (const auto& ancestor : ancestors) {
        auto it = entries_.find(ancestor);
        if (it != entries_.end()) {
            it->second.descendant_count++;
            it->second.descendant_size += tx_size;
            it->second.descendant_fee += fee;
        }
    }

    LOG_DEBUG("Added tx {} to mempool: size={} fee={} rate={:.2f} sat/B",
              crypto::Keccak256::toHex(txid).substr(0, 16), tx_size, fee, fee_rate);

    if (on_tx_added_) {
        on_tx_added_(tx);
    }

    return MempoolReject::VALID;
}

void Mempool::removeTransaction(const crypto::Hash256& txid, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    removeRecursive(txid, reason);
}

void Mempool::removeForBlock(const std::vector<Transaction>& transactions) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& tx : transactions) {
        crypto::Hash256 txid = tx.getTxId();

        // Remove this transaction
        auto it = entries_.find(txid);
        if (it != entries_.end()) {
            // Remove from indices
            by_fee_rate_.erase({it->second.fee_rate, txid});
            total_size_ -= it->second.size;

            // Remove from spent outputs
            for (const auto& input : it->second.tx.inputs) {
                Outpoint outpoint{input.prevout.txid, input.prevout.index};
                spent_outputs_.erase(outpoint);
            }

            // Remove from created outputs
            for (uint32_t i = 0; i < it->second.tx.outputs.size(); i++) {
                Outpoint outpoint{txid, i};
                created_outputs_.erase(outpoint);
            }

            // Update parent/child relationships
            for (const auto& parent : parents_[txid]) {
                children_[parent].erase(txid);
            }
            parents_.erase(txid);

            entries_.erase(it);

            LOG_DEBUG("Removed tx {} from mempool: confirmed", crypto::Keccak256::toHex(txid).substr(0, 16));

            if (on_tx_removed_) {
                on_tx_removed_(txid, "confirmed");
            }
        }

        // Remove conflicting transactions (double spends)
        removeConflicts(tx);
    }
}

void Mempool::removeExpired(int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto expiry_threshold = std::chrono::steady_clock::now() - config_.expiry_time;

    std::vector<crypto::Hash256> to_remove;

    for (const auto& [txid, entry] : entries_) {
        if (entry.time_added < expiry_threshold) {
            to_remove.push_back(txid);
        }
    }

    for (const auto& txid : to_remove) {
        removeRecursive(txid, "expired");
    }
}

bool Mempool::hasTransaction(const crypto::Hash256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.count(txid) > 0;
}

std::optional<Transaction> Mempool::getTransaction(const crypto::Hash256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(txid);
    if (it != entries_.end()) {
        return it->second.tx;
    }

    return std::nullopt;
}

std::optional<MempoolEntry> Mempool::getEntry(const crypto::Hash256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(txid);
    if (it != entries_.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<crypto::Hash256> Mempool::getAllTxIds() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<crypto::Hash256> result;
    result.reserve(entries_.size());

    for (const auto& [txid, entry] : entries_) {
        result.push_back(txid);
    }

    return result;
}

MempoolStats Mempool::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    MempoolStats stats;
    stats.tx_count = entries_.size();
    stats.total_size = total_size_;

    for (const auto& [txid, entry] : entries_) {
        stats.total_fee += entry.fee;
    }

    // Find minimum fee rate
    if (!by_fee_rate_.empty()) {
        stats.min_fee_rate = by_fee_rate_.rbegin()->first;
    }

    // Estimate memory usage
    stats.memory_usage = total_size_ +
        entries_.size() * sizeof(MempoolEntry) +
        spent_outputs_.size() * sizeof(std::pair<Outpoint, crypto::Hash256>) +
        created_outputs_.size() * sizeof(std::pair<Outpoint, crypto::Hash256>);

    return stats;
}

size_t Mempool::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

bool Mempool::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.empty();
}

Mempool::BlockTemplate Mempool::getBlockTemplate(uint64_t max_size, uint64_t max_sigops) const {
    std::lock_guard<std::mutex> lock(mutex_);

    BlockTemplate tmpl;

    // Use ancestor fee rate ordering for optimal fee extraction
    std::vector<std::pair<double, crypto::Hash256>> sorted;
    sorted.reserve(entries_.size());

    for (const auto& [txid, entry] : entries_) {
        double ancestor_fee_rate = entry.getAncestorFeeRate();
        sorted.emplace_back(ancestor_fee_rate, txid);
    }

    // Sort by descending ancestor fee rate
    std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) {
        return a.first > b.first;
    });

    std::set<crypto::Hash256> selected;
    uint64_t current_size = 0;

    for (const auto& [fee_rate, txid] : sorted) {
        if (selected.count(txid) > 0) continue;

        auto it = entries_.find(txid);
        if (it == entries_.end()) continue;

        const MempoolEntry& entry = it->second;

        // Check if all ancestors are selected
        bool ancestors_ok = true;
        std::set<crypto::Hash256> needed_ancestors;

        for (const auto& parent : parents_.at(txid)) {
            if (selected.count(parent) == 0) {
                needed_ancestors.insert(parent);
                // Recursively get all needed ancestors
                auto parent_ancestors = calculateAncestors(parent, 1000);
                for (const auto& pa : parent_ancestors) {
                    if (selected.count(pa) == 0) {
                        needed_ancestors.insert(pa);
                    }
                }
            }
        }

        // Calculate total size needed
        uint64_t needed_size = entry.size;
        uint64_t needed_fee = entry.fee;
        for (const auto& ancestor : needed_ancestors) {
            auto anc_it = entries_.find(ancestor);
            if (anc_it != entries_.end()) {
                needed_size += anc_it->second.size;
                needed_fee += anc_it->second.fee;
            }
        }

        // Check if we have room
        if (current_size + needed_size > max_size) {
            continue;
        }

        // Add ancestors first
        for (const auto& ancestor : needed_ancestors) {
            auto anc_it = entries_.find(ancestor);
            if (anc_it != entries_.end()) {
                tmpl.transactions.push_back(anc_it->second.tx);
                tmpl.total_fee += anc_it->second.fee;
                tmpl.total_size += anc_it->second.size;
                selected.insert(ancestor);
            }
        }

        // Add this transaction
        tmpl.transactions.push_back(entry.tx);
        tmpl.total_fee += entry.fee;
        tmpl.total_size += entry.size;
        selected.insert(txid);

        current_size = tmpl.total_size;
    }

    LOG_DEBUG("Block template: {} txs, {} bytes, {} fee",
              tmpl.transactions.size(), tmpl.total_size, tmpl.total_fee);

    return tmpl;
}

std::set<crypto::Hash256> Mempool::getAncestors(const crypto::Hash256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return calculateAncestors(txid, 1000);
}

std::set<crypto::Hash256> Mempool::getDescendants(const crypto::Hash256& txid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return calculateDescendants(txid, 1000);
}

std::optional<UTXOEntry> Mempool::getUTXO(const Outpoint& outpoint) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if this output is created in mempool
    auto created_it = created_outputs_.find(outpoint);
    if (created_it != created_outputs_.end()) {
        auto entry_it = entries_.find(created_it->second);
        if (entry_it != entries_.end()) {
            const Transaction& tx = entry_it->second.tx;
            if (outpoint.index < tx.outputs.size()) {
                UTXOEntry utxo;
                utxo.value = tx.outputs[outpoint.index].value;
                utxo.script_pubkey = tx.outputs[outpoint.index].script_pubkey;
                utxo.height = 0;  // Unconfirmed
                utxo.coinbase = false;
                return utxo;
            }
        }
    }

    // Check if this output is spent in mempool
    if (spent_outputs_.count(outpoint) > 0) {
        return std::nullopt;
    }

    // Check base UTXO set
    if (utxo_set_) {
        return utxo_set_->getUTXO(outpoint);
    }

    return std::nullopt;
}

void Mempool::clear() {
    std::lock_guard<std::mutex> lock(mutex_);

    entries_.clear();
    by_fee_rate_.clear();
    spent_outputs_.clear();
    created_outputs_.clear();
    parents_.clear();
    children_.clear();
    total_size_ = 0;
}

void Mempool::trimToSize(uint64_t max_size) {
    // Evict lowest fee rate transactions
    while (total_size_ > max_size && !by_fee_rate_.empty()) {
        // Get lowest fee rate transaction
        auto it = by_fee_rate_.rbegin();
        crypto::Hash256 txid = it->second;

        // Remove it and its descendants
        removeRecursive(txid, "evicted");
    }
}

bool Mempool::checkInputs(const Transaction& tx, int32_t current_height,
                          uint64_t& fee, std::string& error) {
    uint64_t total_in = 0;
    uint64_t total_out = 0;

    for (const auto& input : tx.inputs) {
        Outpoint outpoint{input.prevout.txid, input.prevout.index};

        // Check for double spend within mempool
        if (spent_outputs_.count(outpoint) > 0) {
            error = "double spend";
            return false;
        }

        // Look up the output
        std::optional<UTXOEntry> utxo;

        // First check mempool
        auto created_it = created_outputs_.find(outpoint);
        if (created_it != created_outputs_.end()) {
            auto entry_it = entries_.find(created_it->second);
            if (entry_it != entries_.end()) {
                const Transaction& parent_tx = entry_it->second.tx;
                if (outpoint.index < parent_tx.outputs.size()) {
                    UTXOEntry entry;
                    entry.value = parent_tx.outputs[outpoint.index].value;
                    entry.script_pubkey = parent_tx.outputs[outpoint.index].script_pubkey;
                    entry.height = 0;
                    entry.coinbase = false;
                    utxo = entry;
                }
            }
        }

        // Then check UTXO set
        if (!utxo && utxo_set_) {
            utxo = utxo_set_->getUTXO(outpoint);
        }

        if (!utxo) {
            error = "missing inputs";
            return false;
        }

        // Check coinbase maturity
        if (utxo->coinbase && utxo->height > 0) {
            int32_t confirmations = current_height - utxo->height;
            if (confirmations < 100) {  // COINBASE_MATURITY
                error = "immature coinbase";
                return false;
            }
        }

        total_in += utxo->value;
    }

    // Sum outputs
    for (const auto& output : tx.outputs) {
        total_out += output.value;
    }

    // Check fee
    if (total_out > total_in) {
        error = "negative fee";
        return false;
    }

    fee = total_in - total_out;
    return true;
}

void Mempool::updateAncestorDescendantState(const crypto::Hash256& txid) {
    // Recalculate ancestor/descendant counts for this transaction
    auto it = entries_.find(txid);
    if (it == entries_.end()) return;

    auto ancestors = calculateAncestors(txid, config_.max_ancestors + 1);
    auto descendants = calculateDescendants(txid, config_.max_descendants + 1);

    it->second.ancestor_count = ancestors.size();
    it->second.descendant_count = descendants.size();

    uint64_t ancestor_size = it->second.size;
    uint64_t ancestor_fee = it->second.fee;
    for (const auto& ancestor : ancestors) {
        auto anc_it = entries_.find(ancestor);
        if (anc_it != entries_.end()) {
            ancestor_size += anc_it->second.size;
            ancestor_fee += anc_it->second.fee;
        }
    }

    it->second.ancestor_size = ancestor_size;
    it->second.ancestor_fee = ancestor_fee;

    uint64_t descendant_size = it->second.size;
    uint64_t descendant_fee = it->second.fee;
    for (const auto& descendant : descendants) {
        auto desc_it = entries_.find(descendant);
        if (desc_it != entries_.end()) {
            descendant_size += desc_it->second.size;
            descendant_fee += desc_it->second.fee;
        }
    }

    it->second.descendant_size = descendant_size;
    it->second.descendant_fee = descendant_fee;
}

void Mempool::removeConflicts(const Transaction& tx) {
    for (const auto& input : tx.inputs) {
        Outpoint outpoint{input.prevout.txid, input.prevout.index};

        auto it = spent_outputs_.find(outpoint);
        if (it != spent_outputs_.end()) {
            removeRecursive(it->second, "conflict");
        }
    }
}

void Mempool::removeRecursive(const crypto::Hash256& txid, const std::string& reason) {
    auto it = entries_.find(txid);
    if (it == entries_.end()) return;

    // First remove all descendants
    auto children_copy = children_[txid];
    for (const auto& child : children_copy) {
        removeRecursive(child, reason);
    }

    // Now remove this transaction
    const MempoolEntry& entry = it->second;

    // Remove from indices
    by_fee_rate_.erase({entry.fee_rate, txid});
    total_size_ -= entry.size;

    // Remove from spent outputs
    for (const auto& input : entry.tx.inputs) {
        Outpoint outpoint{input.prevout.txid, input.prevout.index};
        spent_outputs_.erase(outpoint);
    }

    // Remove from created outputs
    for (uint32_t i = 0; i < entry.tx.outputs.size(); i++) {
        Outpoint outpoint{txid, i};
        created_outputs_.erase(outpoint);
    }

    // Update parent/child relationships
    for (const auto& parent : parents_[txid]) {
        children_[parent].erase(txid);

        // Update parent's descendant counts
        auto parent_it = entries_.find(parent);
        if (parent_it != entries_.end()) {
            if (parent_it->second.descendant_count > 0) {
                parent_it->second.descendant_count--;
            }
            if (parent_it->second.descendant_size >= entry.size) {
                parent_it->second.descendant_size -= entry.size;
            }
            if (parent_it->second.descendant_fee >= entry.fee) {
                parent_it->second.descendant_fee -= entry.fee;
            }
        }
    }

    parents_.erase(txid);
    children_.erase(txid);

    entries_.erase(it);

    LOG_DEBUG("Removed tx {} from mempool: {}", crypto::Keccak256::toHex(txid).substr(0, 16), reason);

    if (on_tx_removed_) {
        on_tx_removed_(txid, reason);
    }
}

std::set<crypto::Hash256> Mempool::calculateAncestors(const crypto::Hash256& txid,
                                                       uint32_t max_count) const {
    std::set<crypto::Hash256> result;
    std::queue<crypto::Hash256> queue;

    auto it = parents_.find(txid);
    if (it != parents_.end()) {
        for (const auto& parent : it->second) {
            queue.push(parent);
        }
    }

    while (!queue.empty() && result.size() < max_count) {
        crypto::Hash256 current = queue.front();
        queue.pop();

        if (result.count(current) > 0) continue;

        result.insert(current);

        auto parent_it = parents_.find(current);
        if (parent_it != parents_.end()) {
            for (const auto& parent : parent_it->second) {
                if (result.count(parent) == 0) {
                    queue.push(parent);
                }
            }
        }
    }

    return result;
}

std::set<crypto::Hash256> Mempool::calculateDescendants(const crypto::Hash256& txid,
                                                         uint32_t max_count) const {
    std::set<crypto::Hash256> result;
    std::queue<crypto::Hash256> queue;

    auto it = children_.find(txid);
    if (it != children_.end()) {
        for (const auto& child : it->second) {
            queue.push(child);
        }
    }

    while (!queue.empty() && result.size() < max_count) {
        crypto::Hash256 current = queue.front();
        queue.pop();

        if (result.count(current) > 0) continue;

        result.insert(current);

        auto child_it = children_.find(current);
        if (child_it != children_.end()) {
            for (const auto& child : child_it->second) {
                if (result.count(child) == 0) {
                    queue.push(child);
                }
            }
        }
    }

    return result;
}

bool Mempool::checkLimits(const std::set<crypto::Hash256>& ancestors,
                          const std::set<crypto::Hash256>& descendants) const {
    if (ancestors.size() > config_.max_ancestors) {
        return false;
    }

    if (descendants.size() > config_.max_descendants) {
        return false;
    }

    uint64_t ancestor_size = 0;
    for (const auto& ancestor : ancestors) {
        auto it = entries_.find(ancestor);
        if (it != entries_.end()) {
            ancestor_size += it->second.size;
        }
    }

    if (ancestor_size > config_.max_ancestor_size) {
        return false;
    }

    uint64_t descendant_size = 0;
    for (const auto& descendant : descendants) {
        auto it = entries_.find(descendant);
        if (it != entries_.end()) {
            descendant_size += it->second.size;
        }
    }

    if (descendant_size > config_.max_descendant_size) {
        return false;
    }

    return true;
}

} // namespace chain
} // namespace ftc
