#ifndef FTC_CHAIN_MEMPOOL_H
#define FTC_CHAIN_MEMPOOL_H

#include "chain/transaction.h"
#include "chain/utxo_set.h"
#include "crypto/keccak256.h"
#include <map>
#include <set>
#include <vector>
#include <list>
#include <mutex>
#include <optional>
#include <functional>
#include <chrono>

namespace ftc {
namespace chain {

// Forward declarations
class Chain;

// Mempool entry - transaction with metadata
struct MempoolEntry {
    Transaction tx;
    crypto::Hash256 txid;
    uint64_t fee = 0;                   // Transaction fee in satoshis
    uint64_t size = 0;                  // Transaction size in bytes
    double fee_rate = 0.0;              // Fee per byte (satoshis/byte)
    std::chrono::steady_clock::time_point time_added;
    int32_t height_added = 0;           // Chain height when added

    // Ancestor/descendant tracking
    uint64_t ancestor_count = 0;        // Number of unconfirmed ancestors
    uint64_t ancestor_size = 0;         // Total size of ancestors
    uint64_t ancestor_fee = 0;          // Total fee of ancestors
    uint64_t descendant_count = 0;      // Number of unconfirmed descendants
    uint64_t descendant_size = 0;       // Total size of descendants
    uint64_t descendant_fee = 0;        // Total fee of descendants

    // For sorting by ancestor fee rate
    double getAncestorFeeRate() const {
        return ancestor_size > 0 ? static_cast<double>(ancestor_fee) / ancestor_size : 0.0;
    }

    // Comparison for priority ordering
    bool operator<(const MempoolEntry& other) const {
        // Higher fee rate = higher priority
        return fee_rate > other.fee_rate;
    }
};

// Mempool statistics
struct MempoolStats {
    uint64_t tx_count = 0;
    uint64_t total_size = 0;            // Total bytes
    uint64_t total_fee = 0;             // Total fees
    double min_fee_rate = 0.0;          // Minimum fee rate to enter
    uint64_t memory_usage = 0;          // Estimated memory usage
};

// Rejection reason
enum class MempoolReject {
    VALID,
    ALREADY_IN_MEMPOOL,
    ALREADY_IN_CHAIN,
    MISSING_INPUTS,
    DOUBLE_SPEND,
    IMMATURE_COINBASE,
    NEGATIVE_FEE,
    INSUFFICIENT_FEE,
    TOO_LARGE,
    SCRIPT_ERROR,
    MEMPOOL_FULL,
    ANCESTOR_LIMIT,
    DESCENDANT_LIMIT
};

// Callbacks
using TxAddedCallback = std::function<void(const Transaction&)>;
using TxRemovedCallback = std::function<void(const crypto::Hash256&, const std::string&)>;

/**
 * Mempool - manages unconfirmed transactions
 *
 * Provides:
 * - Transaction acceptance and validation
 * - Fee-based transaction ordering
 * - Ancestor/descendant tracking for CPFP
 * - Block template generation
 * - Eviction policy for full mempool
 */
class Mempool {
public:
    // Configuration
    struct Config {
        uint64_t max_size = 300 * 1024 * 1024;      // 300 MB
        uint64_t max_tx_size = 100000;               // 100 KB per tx
        uint64_t min_relay_fee = 1000;               // 1000 sat/KB minimum
        uint32_t max_ancestors = 25;
        uint32_t max_descendants = 25;
        uint64_t max_ancestor_size = 101000;         // 101 KB
        uint64_t max_descendant_size = 101000;       // 101 KB
        std::chrono::hours expiry_time{336};         // 2 weeks

        Config() = default;
    };

    Mempool();
    explicit Mempool(const Config& config);
    ~Mempool();

    // Non-copyable
    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;

    // Set UTXO set reference
    void setUTXOSet(UTXOSet* utxo_set) { utxo_set_ = utxo_set; }

    // Set chain reference
    void setChain(Chain* chain) { chain_ = chain; }

    // Set callbacks
    void setTxAddedCallback(TxAddedCallback cb) { on_tx_added_ = cb; }
    void setTxRemovedCallback(TxRemovedCallback cb) { on_tx_removed_ = cb; }

    // Callback setters (aliases for node.cpp compatibility)
    void setOnTxAdded(TxAddedCallback cb) { on_tx_added_ = cb; }
    void setOnTxRemoved(TxRemovedCallback cb) { on_tx_removed_ = cb; }

    // Add transaction
    MempoolReject addTransaction(const Transaction& tx, int32_t current_height);
    MempoolReject add(const Transaction& tx, int32_t current_height) { return addTransaction(tx, current_height); }  // Alias

    // Remove transactions
    void removeTransaction(const crypto::Hash256& txid, const std::string& reason = "");
    void removeForBlock(const std::vector<Transaction>& transactions);
    void removeExpired(int64_t now);

    // Query
    bool hasTransaction(const crypto::Hash256& txid) const;
    bool has(const crypto::Hash256& txid) const { return hasTransaction(txid); }  // Alias
    std::optional<Transaction> getTransaction(const crypto::Hash256& txid) const;
    std::optional<Transaction> get(const crypto::Hash256& txid) const { return getTransaction(txid); }  // Alias
    std::optional<MempoolEntry> getEntry(const crypto::Hash256& txid) const;
    std::vector<crypto::Hash256> getAllTxIds() const;
    std::vector<crypto::Hash256> getAllTxids() const { return getAllTxIds(); }  // Alias (lowercase)

    // Statistics
    MempoolStats getStats() const;
    size_t size() const;
    bool empty() const;

    // Block template generation
    struct BlockTemplate {
        std::vector<Transaction> transactions;
        uint64_t total_fee = 0;
        uint64_t total_size = 0;
    };

    BlockTemplate getBlockTemplate(uint64_t max_size, uint64_t max_sigops = 20000) const;

    // Ancestor/descendant queries
    std::set<crypto::Hash256> getAncestors(const crypto::Hash256& txid) const;
    std::set<crypto::Hash256> getDescendants(const crypto::Hash256& txid) const;

    // UTXO view with mempool
    std::optional<UTXOEntry> getUTXO(const Outpoint& outpoint) const;

    // Clear mempool
    void clear();

    // Trim mempool to size
    void trimToSize(uint64_t max_size);

private:
    // Internal entry storage
    std::map<crypto::Hash256, MempoolEntry> entries_;

    // Index by fee rate for eviction
    std::multiset<std::pair<double, crypto::Hash256>> by_fee_rate_;

    // Spent outpoints in mempool (for double-spend detection)
    std::map<Outpoint, crypto::Hash256> spent_outputs_;

    // Created UTXOs in mempool (for chaining)
    std::map<Outpoint, crypto::Hash256> created_outputs_;

    // Parent/child relationships
    std::map<crypto::Hash256, std::set<crypto::Hash256>> parents_;    // tx -> parents
    std::map<crypto::Hash256, std::set<crypto::Hash256>> children_;   // tx -> children

    // Mutex
    mutable std::mutex mutex_;

    // Configuration
    Config config_;

    // External references
    UTXOSet* utxo_set_ = nullptr;
    Chain* chain_ = nullptr;

    // Callbacks
    TxAddedCallback on_tx_added_;
    TxRemovedCallback on_tx_removed_;

    // Total size
    uint64_t total_size_ = 0;

    // Internal methods
    bool checkInputs(const Transaction& tx, int32_t current_height,
                     uint64_t& fee, std::string& error);
    void updateAncestorDescendantState(const crypto::Hash256& txid);
    void removeConflicts(const Transaction& tx);
    void removeRecursive(const crypto::Hash256& txid, const std::string& reason);
    std::set<crypto::Hash256> calculateAncestors(const crypto::Hash256& txid,
                                                  uint32_t max_count = 1000) const;
    std::set<crypto::Hash256> calculateDescendants(const crypto::Hash256& txid,
                                                    uint32_t max_count = 1000) const;
    bool checkLimits(const std::set<crypto::Hash256>& ancestors,
                     const std::set<crypto::Hash256>& descendants) const;
};

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_MEMPOOL_H
