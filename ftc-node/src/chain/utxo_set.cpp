/**
 * FTC UTXO Set Implementation
 * Full unspent transaction output management
 */

#include "chain/utxo_set.h"
#include "util/logging.h"
#include <fstream>
#include <filesystem>
#include <cstring>

namespace ftc {
namespace chain {

namespace fs = std::filesystem;

// ============================================================================
// UTXOEntry implementation
// ============================================================================

std::vector<uint8_t> UTXOEntry::serialize() const {
    std::vector<uint8_t> data;

    // Value (8 bytes)
    for (int i = 0; i < 8; i++) {
        data.push_back((value >> (i * 8)) & 0xFF);
    }

    // Height (4 bytes)
    for (int i = 0; i < 4; i++) {
        data.push_back((height >> (i * 8)) & 0xFF);
    }

    // Coinbase flag (1 byte)
    data.push_back(coinbase ? 1 : 0);

    // Script length (varint-style, simplified to 2 bytes)
    uint16_t script_len = static_cast<uint16_t>(script_pubkey.size());
    data.push_back(script_len & 0xFF);
    data.push_back((script_len >> 8) & 0xFF);

    // Script
    data.insert(data.end(), script_pubkey.begin(), script_pubkey.end());

    return data;
}

bool UTXOEntry::deserialize(const uint8_t* data, size_t len) {
    if (len < 15) return false;  // Minimum: 8 + 4 + 1 + 2 = 15 bytes

    size_t pos = 0;

    // Value
    value = 0;
    for (int i = 0; i < 8; i++) {
        value |= static_cast<uint64_t>(data[pos++]) << (i * 8);
    }

    // Height
    height = 0;
    for (int i = 0; i < 4; i++) {
        height |= static_cast<int32_t>(data[pos++]) << (i * 8);
    }

    // Coinbase
    coinbase = (data[pos++] != 0);

    // Script length
    uint16_t script_len = data[pos] | (data[pos + 1] << 8);
    pos += 2;

    if (pos + script_len > len) return false;

    // Script
    script_pubkey.assign(data + pos, data + pos + script_len);

    return true;
}

// ============================================================================
// CoinViewDelta implementation
// ============================================================================

void CoinViewDelta::addUTXO(const Outpoint& outpoint, const UTXOEntry& entry) {
    // If this was previously spent, remove from spent set
    spent.erase(outpoint);
    added[outpoint] = entry;
}

void CoinViewDelta::spendUTXO(const Outpoint& outpoint) {
    // If this was added in this delta, just remove it
    auto it = added.find(outpoint);
    if (it != added.end()) {
        added.erase(it);
    } else {
        spent.insert(outpoint);
    }
}

void CoinViewDelta::clear() {
    added.clear();
    spent.clear();
}

bool CoinViewDelta::isEmpty() const {
    return added.empty() && spent.empty();
}

// ============================================================================
// UTXOSet implementation
// ============================================================================

UTXOSet::UTXOSet() {}

UTXOSet::~UTXOSet() {
    close();
}

bool UTXOSet::load(const std::string& path) {
    path_ = path;

    try {
        fs::create_directories(path_);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create UTXO directory: {}", e.what());
        return false;
    }

    if (!loadFromDisk()) {
        LOG_INFO("Starting with empty UTXO set");
    }

    LOG_INFO("UTXO set loaded: {} entries", utxos_.size());
    return true;
}

void UTXOSet::close() {
    flush();
}

void UTXOSet::flush() {
    if (dirty_) {
        saveToDisk();
        dirty_ = false;
    }
}

std::optional<UTXOEntry> UTXOSet::getUTXO(const Outpoint& outpoint) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = utxos_.find(outpoint);
    if (it != utxos_.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool UTXOSet::hasUTXO(const Outpoint& outpoint) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return utxos_.count(outpoint) > 0;
}

uint64_t UTXOSet::getUTXOCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return utxos_.size();
}

AddressBalance UTXOSet::getBalance(const std::vector<uint8_t>& script_pubkey) const {
    std::lock_guard<std::mutex> lock(mutex_);

    AddressBalance balance;

    auto it = address_index_.find(script_pubkey);
    if (it == address_index_.end()) {
        return balance;
    }

    for (const auto& outpoint : it->second) {
        auto utxo_it = utxos_.find(outpoint);
        if (utxo_it != utxos_.end()) {
            balance.confirmed += utxo_it->second.value;

            AddressUTXO addr_utxo;
            addr_utxo.outpoint = outpoint;
            addr_utxo.value = utxo_it->second.value;
            addr_utxo.height = utxo_it->second.height;
            addr_utxo.coinbase = utxo_it->second.coinbase;
            balance.utxos.push_back(addr_utxo);
        }
    }

    return balance;
}

std::vector<AddressUTXO> UTXOSet::getUTXOs(const std::vector<uint8_t>& script_pubkey) const {
    return getBalance(script_pubkey).utxos;
}

UTXOSet::TxValidation UTXOSet::validateTransaction(const Transaction& tx, int32_t current_height,
                                                    uint64_t* fee_out) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Coinbase transactions have no inputs to validate
    if (tx.isCoinbase()) {
        if (fee_out) *fee_out = 0;
        return TxValidation::VALID;
    }

    uint64_t total_in = 0;
    uint64_t total_out = 0;

    // Check all inputs
    for (const auto& input : tx.inputs) {
        Outpoint outpoint{input.prevout.txid, input.prevout.index};

        auto it = utxos_.find(outpoint);
        if (it == utxos_.end()) {
            return TxValidation::MISSING_INPUTS;
        }

        const UTXOEntry& utxo = it->second;

        // Check coinbase maturity
        if (utxo.coinbase) {
            int32_t confirmations = current_height - utxo.height;
            if (confirmations < COINBASE_MATURITY) {
                return TxValidation::IMMATURE_COINBASE;
            }
        }

        total_in += utxo.value;
    }

    // Sum outputs
    for (const auto& output : tx.outputs) {
        total_out += output.value;
    }

    // Check fee
    if (total_out > total_in) {
        return TxValidation::NEGATIVE_FEE;
    }

    if (fee_out) {
        *fee_out = total_in - total_out;
    }

    return TxValidation::VALID;
}

bool UTXOSet::connectBlock(const std::vector<Transaction>& transactions, int32_t height) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (size_t tx_idx = 0; tx_idx < transactions.size(); tx_idx++) {
        const Transaction& tx = transactions[tx_idx];
        crypto::Hash256 txid = tx.getTxId();

        bool is_coinbase = (tx_idx == 0);

        // Spend inputs (skip for coinbase)
        if (!is_coinbase) {
            for (const auto& input : tx.inputs) {
                Outpoint outpoint{input.prevout.txid, input.prevout.index};
                removeUTXOInternal(outpoint);
            }
        }

        // Add outputs
        for (uint32_t i = 0; i < tx.outputs.size(); i++) {
            const TxOutput& output = tx.outputs[i];

            Outpoint outpoint{txid, i};
            UTXOEntry entry;
            entry.value = output.value;
            entry.script_pubkey = output.script_pubkey;
            entry.height = height;
            entry.coinbase = is_coinbase;

            addUTXOInternal(outpoint, entry);
        }
    }

    dirty_ = true;
    return true;
}

bool UTXOSet::disconnectBlock(const std::vector<Transaction>& transactions, int32_t height,
                               const CoinViewDelta& undo_data) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Process transactions in reverse order
    for (auto tx_it = transactions.rbegin(); tx_it != transactions.rend(); ++tx_it) {
        const Transaction& tx = *tx_it;
        crypto::Hash256 txid = tx.getTxId();

        // Remove outputs
        for (uint32_t i = 0; i < tx.outputs.size(); i++) {
            Outpoint outpoint{txid, i};
            removeUTXOInternal(outpoint);
        }

        // Restore inputs (from undo data)
        if (!tx.isCoinbase()) {
            for (const auto& input : tx.inputs) {
                Outpoint outpoint{input.prevout.txid, input.prevout.index};

                auto it = undo_data.added.find(outpoint);
                if (it != undo_data.added.end()) {
                    addUTXOInternal(outpoint, it->second);
                }
            }
        }
    }

    dirty_ = true;
    return true;
}

CoinViewDelta UTXOSet::createDelta() const {
    return CoinViewDelta{};
}

bool UTXOSet::applyDelta(const CoinViewDelta& delta) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Remove spent UTXOs
    for (const auto& outpoint : delta.spent) {
        removeUTXOInternal(outpoint);
    }

    // Add new UTXOs
    for (const auto& [outpoint, entry] : delta.added) {
        addUTXOInternal(outpoint, entry);
    }

    dirty_ = true;
    return true;
}

CoinViewDelta UTXOSet::generateUndoData(const std::vector<Transaction>& transactions) const {
    std::lock_guard<std::mutex> lock(mutex_);

    CoinViewDelta undo;

    for (const auto& tx : transactions) {
        if (tx.isCoinbase()) continue;

        for (const auto& input : tx.inputs) {
            Outpoint outpoint{input.prevout.txid, input.prevout.index};

            auto it = utxos_.find(outpoint);
            if (it != utxos_.end()) {
                undo.added[outpoint] = it->second;
            }
        }
    }

    return undo;
}

uint64_t UTXOSet::getTotalValue() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& [outpoint, entry] : utxos_) {
        total += entry.value;
    }

    return total;
}

size_t UTXOSet::getMemoryUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t usage = 0;

    // UTXO map
    for (const auto& [outpoint, entry] : utxos_) {
        usage += sizeof(outpoint) + sizeof(entry) + entry.script_pubkey.size();
    }

    // Address index
    for (const auto& [script, outpoints] : address_index_) {
        usage += script.size() + outpoints.size() * sizeof(Outpoint);
    }

    return usage;
}

void UTXOSet::forEachUTXO(UTXOCallback callback) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& [outpoint, entry] : utxos_) {
        callback(outpoint, entry);
    }
}

void UTXOSet::importUTXO(const Outpoint& outpoint, const UTXOEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    addUTXOInternal(outpoint, entry);
    dirty_ = true;
}

void UTXOSet::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    utxos_.clear();
    address_index_.clear();
    dirty_ = true;
    LOG_INFO("UTXO set cleared");
}

void UTXOSet::addUTXOInternal(const Outpoint& outpoint, const UTXOEntry& entry) {
    utxos_[outpoint] = entry;

    // Update address index
    address_index_[entry.script_pubkey].insert(outpoint);
}

void UTXOSet::removeUTXOInternal(const Outpoint& outpoint) {
    auto it = utxos_.find(outpoint);
    if (it != utxos_.end()) {
        // Update address index
        auto& script = it->second.script_pubkey;
        auto addr_it = address_index_.find(script);
        if (addr_it != address_index_.end()) {
            addr_it->second.erase(outpoint);
            if (addr_it->second.empty()) {
                address_index_.erase(addr_it);
            }
        }

        utxos_.erase(it);
    }
}

bool UTXOSet::loadFromDisk() {
    std::string file_path = path_ + "/utxo.dat";

    if (!fs::exists(file_path)) {
        return false;
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        return false;
    }

    // Read count
    uint64_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));

    for (uint64_t i = 0; i < count; i++) {
        // Read outpoint
        Outpoint outpoint;
        file.read(reinterpret_cast<char*>(outpoint.txid.data()), 32);
        file.read(reinterpret_cast<char*>(&outpoint.index), sizeof(outpoint.index));

        // Read entry size and data
        uint32_t entry_size;
        file.read(reinterpret_cast<char*>(&entry_size), sizeof(entry_size));

        std::vector<uint8_t> entry_data(entry_size);
        file.read(reinterpret_cast<char*>(entry_data.data()), entry_size);

        UTXOEntry entry;
        if (entry.deserialize(entry_data.data(), entry_data.size())) {
            addUTXOInternal(outpoint, entry);
        }
    }

    return true;
}

bool UTXOSet::saveToDisk() {
    std::string file_path = path_ + "/utxo.dat";
    std::string temp_path = file_path + ".tmp";

    std::ofstream file(temp_path, std::ios::binary);
    if (!file) {
        LOG_ERROR("Failed to open UTXO file for writing");
        return false;
    }

    // Write count
    uint64_t count = utxos_.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& [outpoint, entry] : utxos_) {
        // Write outpoint
        file.write(reinterpret_cast<const char*>(outpoint.txid.data()), 32);
        file.write(reinterpret_cast<const char*>(&outpoint.index), sizeof(outpoint.index));

        // Write entry
        auto entry_data = entry.serialize();
        uint32_t entry_size = static_cast<uint32_t>(entry_data.size());
        file.write(reinterpret_cast<const char*>(&entry_size), sizeof(entry_size));
        file.write(reinterpret_cast<const char*>(entry_data.data()), entry_data.size());
    }

    file.close();

    // Atomic rename
    try {
        fs::rename(temp_path, file_path);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to rename UTXO file: {}", e.what());
        return false;
    }

    LOG_DEBUG("Saved {} UTXOs to disk", count);
    return true;
}

// ============================================================================
// CoinCache implementation
// ============================================================================

CoinCache::CoinCache(UTXOSet& base) : base_(base) {}

std::optional<UTXOEntry> CoinCache::getUTXO(const Outpoint& outpoint) const {
    // Check if spent in delta
    if (delta_.spent.count(outpoint) > 0) {
        return std::nullopt;
    }

    // Check if added in delta
    auto it = delta_.added.find(outpoint);
    if (it != delta_.added.end()) {
        return it->second;
    }

    // Check base
    return base_.getUTXO(outpoint);
}

bool CoinCache::hasUTXO(const Outpoint& outpoint) const {
    return getUTXO(outpoint).has_value();
}

void CoinCache::addUTXO(const Outpoint& outpoint, const UTXOEntry& entry) {
    delta_.addUTXO(outpoint, entry);
}

void CoinCache::spendUTXO(const Outpoint& outpoint) {
    // Fetch from base if not already in delta
    if (delta_.added.count(outpoint) == 0 && fetched_.count(outpoint) == 0) {
        auto entry = base_.getUTXO(outpoint);
        if (entry) {
            // Store original for undo
            delta_.added[outpoint] = *entry;
            fetched_.insert(outpoint);
        }
    }

    delta_.spendUTXO(outpoint);
}

bool CoinCache::flush() {
    if (delta_.isEmpty()) {
        return true;
    }

    bool success = base_.applyDelta(delta_);
    if (success) {
        clear();
    }

    return success;
}

void CoinCache::clear() {
    delta_.clear();
    fetched_.clear();
}

// ============================================================================
// UTXOSet - Additional implementations
// ============================================================================

UTXOSet::UTXOSet(const Config& config) : config_(config) {}

bool UTXOSet::open() {
    return load(config_.db_path);
}

} // namespace chain
} // namespace ftc
