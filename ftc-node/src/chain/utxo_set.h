#ifndef FTC_CHAIN_UTXO_SET_H
#define FTC_CHAIN_UTXO_SET_H

#include "chain/transaction.h"
#include "crypto/keccak256.h"
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <optional>
#include <functional>
#include <memory>

namespace ftc {
namespace chain {

// Outpoint - alias for OutPoint (defined in transaction.h)
// Standardized to avoid type duplication
using Outpoint = OutPoint;

// UTXO entry - unspent transaction output
struct UTXOEntry {
    uint64_t value = 0;                     // Amount in satoshis
    std::vector<uint8_t> script_pubkey;     // Locking script
    int32_t height = 0;                     // Block height where created
    bool coinbase = false;                  // Is this from a coinbase tx?

    // Serialization
    std::vector<uint8_t> serialize() const;
    bool deserialize(const uint8_t* data, size_t len);
};

// UTXO for a specific address
struct AddressUTXO {
    Outpoint outpoint;
    uint64_t value = 0;
    int32_t height = 0;
    bool coinbase = false;
};

// Coin view delta - changes to be applied to UTXO set
struct CoinViewDelta {
    std::map<Outpoint, UTXOEntry> added;
    std::set<Outpoint> spent;

    void addUTXO(const Outpoint& outpoint, const UTXOEntry& entry);
    void spendUTXO(const Outpoint& outpoint);
    void clear();
    bool isEmpty() const;
};

// Address index entry
struct AddressBalance {
    uint64_t confirmed = 0;
    uint64_t unconfirmed = 0;
    std::vector<AddressUTXO> utxos;
};

/**
 * UTXOSet - manages unspent transaction outputs
 *
 * Core component for validating transactions and calculating balances.
 * Provides:
 * - UTXO lookup by outpoint
 * - Balance calculation by address
 * - Transaction validation
 * - Block connect/disconnect support
 */
class UTXOSet {
public:
    // Configuration
    struct Config {
        std::string db_path = "./chainstate";
        size_t cache_size = 450 * 1024 * 1024;  // 450 MB default
        bool verify_checksums = true;
    };

    UTXOSet();
    explicit UTXOSet(const Config& config);
    ~UTXOSet();

    // Non-copyable
    UTXOSet(const UTXOSet&) = delete;
    UTXOSet& operator=(const UTXOSet&) = delete;

    // Initialization
    bool load(const std::string& path);
    bool open();        // Open using configured path
    void close();
    void flush();

    // UTXO access
    std::optional<UTXOEntry> getUTXO(const Outpoint& outpoint) const;
    bool hasUTXO(const Outpoint& outpoint) const;
    bool has(const Outpoint& outpoint) const { return hasUTXO(outpoint); }  // Alias
    uint64_t getUTXOCount() const;
    size_t size() const { return static_cast<size_t>(getUTXOCount()); }  // Alias

    // Address queries
    AddressBalance getBalance(const std::vector<uint8_t>& script_pubkey) const;
    std::vector<AddressUTXO> getUTXOs(const std::vector<uint8_t>& script_pubkey) const;

    // Transaction validation
    enum class TxValidation {
        VALID,
        MISSING_INPUTS,
        DOUBLE_SPEND,
        IMMATURE_COINBASE,
        NEGATIVE_FEE,
        INSUFFICIENT_FEE,
        SCRIPT_ERROR
    };

    TxValidation validateTransaction(const Transaction& tx, int32_t current_height,
                                     uint64_t* fee_out = nullptr) const;

    // Block operations
    bool connectBlock(const std::vector<Transaction>& transactions, int32_t height);
    bool disconnectBlock(const std::vector<Transaction>& transactions, int32_t height,
                         const CoinViewDelta& undo_data);

    // Delta operations (for mempool)
    CoinViewDelta createDelta() const;
    bool applyDelta(const CoinViewDelta& delta);

    // Undo data generation
    CoinViewDelta generateUndoData(const std::vector<Transaction>& transactions) const;

    // Statistics
    uint64_t getTotalValue() const;
    size_t getMemoryUsage() const;

    // Snapshot support
    using UTXOCallback = std::function<void(const Outpoint&, const UTXOEntry&)>;
    void forEachUTXO(UTXOCallback callback) const;
    void importUTXO(const Outpoint& outpoint, const UTXOEntry& entry);
    void clear();
    void setSnapshotHeight(int32_t height) { snapshot_height_ = height; }
    int32_t getSnapshotHeight() const { return snapshot_height_; }

private:
    // Configuration
    Config config_;

    // Internal UTXO storage
    std::map<Outpoint, UTXOEntry> utxos_;
    mutable std::mutex mutex_;

    // Address index (script_pubkey -> outpoints)
    std::map<std::vector<uint8_t>, std::set<Outpoint>> address_index_;

    // Persistence
    std::string path_;
    bool dirty_ = false;
    int32_t snapshot_height_ = -1;  // Height from imported snapshot, -1 if none

    // Coinbase maturity (100 blocks like Bitcoin)
    static constexpr int COINBASE_MATURITY = 100;

    // Internal methods
    void addUTXOInternal(const Outpoint& outpoint, const UTXOEntry& entry);
    void removeUTXOInternal(const Outpoint& outpoint);
    bool loadFromDisk();
    bool saveToDisk();
};

/**
 * CoinCache - layered UTXO cache for efficient access
 *
 * Provides a write-through cache on top of the base UTXO set
 * for faster transaction validation during block processing.
 */
class CoinCache {
public:
    CoinCache(UTXOSet& base);

    std::optional<UTXOEntry> getUTXO(const Outpoint& outpoint) const;
    bool hasUTXO(const Outpoint& outpoint) const;

    void addUTXO(const Outpoint& outpoint, const UTXOEntry& entry);
    void spendUTXO(const Outpoint& outpoint);

    // Flush changes to base
    bool flush();

    // Discard changes
    void clear();

    // Get delta for undo
    const CoinViewDelta& getDelta() const { return delta_; }

private:
    UTXOSet& base_;
    CoinViewDelta delta_;
    std::set<Outpoint> fetched_;
};

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_UTXO_SET_H
