/**
 * FTC P2Pool Sharechain Implementation
 *
 * Manages the secondary chain of shares for decentralized mining pool.
 * Each share is a proof-of-work at lower difficulty than the main chain.
 */

#include "p2pool/sharechain.h"
#include "util/logging.h"
#include "crypto/keccak256.h"
#include "chain/consensus.h"

#include <fstream>
#include <filesystem>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace ftc {
namespace p2pool {

// Helper functions for Hash256
static bool isZeroHash(const crypto::Hash256& hash) {
    for (const auto& byte : hash) {
        if (byte != 0) return false;
    }
    return true;
}

static std::string hashToHex(const crypto::Hash256& hash) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto& byte : hash) {
        result += hex_chars[(byte >> 4) & 0x0F];
        result += hex_chars[byte & 0x0F];
    }
    return result;
}

// ============================================================================
// ShareHeader implementation
// ============================================================================

std::vector<uint8_t> ShareHeader::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(4 + 32 + 32 + 4 + 4 + 4 + 32 + 4 + 4);

    // Version
    data.push_back(version & 0xFF);
    data.push_back((version >> 8) & 0xFF);
    data.push_back((version >> 16) & 0xFF);
    data.push_back((version >> 24) & 0xFF);

    // Previous share
    data.insert(data.end(), prev_share.begin(), prev_share.end());

    // Merkle root
    data.insert(data.end(), merkle_root.begin(), merkle_root.end());

    // Timestamp
    data.push_back(timestamp & 0xFF);
    data.push_back((timestamp >> 8) & 0xFF);
    data.push_back((timestamp >> 16) & 0xFF);
    data.push_back((timestamp >> 24) & 0xFF);

    // Share bits
    data.push_back(bits & 0xFF);
    data.push_back((bits >> 8) & 0xFF);
    data.push_back((bits >> 16) & 0xFF);
    data.push_back((bits >> 24) & 0xFF);

    // Nonce
    data.push_back(nonce & 0xFF);
    data.push_back((nonce >> 8) & 0xFF);
    data.push_back((nonce >> 16) & 0xFF);
    data.push_back((nonce >> 24) & 0xFF);

    // Block prev hash
    data.insert(data.end(), block_prev_hash.begin(), block_prev_hash.end());

    // Block height
    data.push_back(block_height & 0xFF);
    data.push_back((block_height >> 8) & 0xFF);
    data.push_back((block_height >> 16) & 0xFF);
    data.push_back((block_height >> 24) & 0xFF);

    // Block bits
    data.push_back(block_bits & 0xFF);
    data.push_back((block_bits >> 8) & 0xFF);
    data.push_back((block_bits >> 16) & 0xFF);
    data.push_back((block_bits >> 24) & 0xFF);

    return data;
}

bool ShareHeader::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 116) return false;

    size_t pos = 0;

    version = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    std::copy(data.begin() + pos, data.begin() + pos + 32, prev_share.begin());
    pos += 32;

    std::copy(data.begin() + pos, data.begin() + pos + 32, merkle_root.begin());
    pos += 32;

    timestamp = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    bits = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    nonce = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    std::copy(data.begin() + pos, data.begin() + pos + 32, block_prev_hash.begin());
    pos += 32;

    block_height = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
    pos += 4;

    block_bits = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);

    return true;
}

crypto::Hash256 ShareHeader::hash() const {
    auto data = serialize();
    return crypto::keccak256(data.data(), data.size());
}

// ============================================================================
// Share implementation
// ============================================================================

uint64_t Share::getDifficulty() const {
    // Calculate difficulty from bits
    uint32_t exp = header.bits >> 24;
    uint32_t mantissa = header.bits & 0x00FFFFFF;

    if (exp <= 3) {
        return mantissa >> (8 * (3 - exp));
    } else {
        return static_cast<uint64_t>(mantissa) << (8 * (exp - 3));
    }
}

std::vector<uint8_t> Share::serialize() const {
    std::vector<uint8_t> data;

    // Header
    auto header_data = header.serialize();
    data.insert(data.end(), header_data.begin(), header_data.end());

    // Payout count (varint)
    uint64_t payout_count = payouts.size();
    while (payout_count >= 0x80) {
        data.push_back((payout_count & 0x7F) | 0x80);
        payout_count >>= 7;
    }
    data.push_back(payout_count);

    // Payouts
    for (const auto& payout : payouts) {
        // Script length (varint)
        uint64_t script_len = payout.script_pubkey.size();
        while (script_len >= 0x80) {
            data.push_back((script_len & 0x7F) | 0x80);
            script_len >>= 7;
        }
        data.push_back(script_len);

        // Script
        data.insert(data.end(), payout.script_pubkey.begin(), payout.script_pubkey.end());

        // Weight
        for (int i = 0; i < 8; i++) {
            data.push_back((payout.weight >> (i * 8)) & 0xFF);
        }
    }

    // Generation transaction
    auto gen_data = generation_tx.serialize();
    uint64_t gen_len = gen_data.size();
    while (gen_len >= 0x80) {
        data.push_back((gen_len & 0x7F) | 0x80);
        gen_len >>= 7;
    }
    data.push_back(gen_len);
    data.insert(data.end(), gen_data.begin(), gen_data.end());

    // Transaction hashes count
    uint64_t tx_count = tx_hashes.size();
    while (tx_count >= 0x80) {
        data.push_back((tx_count & 0x7F) | 0x80);
        tx_count >>= 7;
    }
    data.push_back(tx_count);

    // Transaction hashes
    for (const auto& txhash : tx_hashes) {
        data.insert(data.end(), txhash.begin(), txhash.end());
    }

    return data;
}

bool Share::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 116) return false;

    size_t pos = 0;

    // Header
    if (!header.deserialize(std::vector<uint8_t>(data.begin(), data.begin() + 116))) {
        return false;
    }
    pos = 116;

    auto readVarint = [&data, &pos]() -> uint64_t {
        uint64_t result = 0;
        int shift = 0;
        while (pos < data.size()) {
            uint8_t byte = data[pos++];
            result |= static_cast<uint64_t>(byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    };

    // Payouts
    uint64_t payout_count = readVarint();
    payouts.clear();
    payouts.reserve(payout_count);

    for (uint64_t i = 0; i < payout_count && pos < data.size(); i++) {
        PayoutEntry entry;

        uint64_t script_len = readVarint();
        if (pos + script_len > data.size()) return false;
        entry.script_pubkey.assign(data.begin() + pos, data.begin() + pos + script_len);
        pos += script_len;

        if (pos + 8 > data.size()) return false;
        entry.weight = 0;
        for (int j = 0; j < 8; j++) {
            entry.weight |= static_cast<uint64_t>(data[pos + j]) << (j * 8);
        }
        pos += 8;

        payouts.push_back(entry);
    }

    // Generation transaction
    uint64_t gen_len = readVarint();
    if (pos + gen_len > data.size()) return false;
    if (!generation_tx.deserialize(std::vector<uint8_t>(data.begin() + pos, data.begin() + pos + gen_len))) {
        return false;
    }
    pos += gen_len;

    // Transaction hashes
    uint64_t tx_count = readVarint();
    tx_hashes.clear();
    tx_hashes.reserve(tx_count);

    for (uint64_t i = 0; i < tx_count && pos + 32 <= data.size(); i++) {
        crypto::Hash256 txhash;
        std::copy(data.begin() + pos, data.begin() + pos + 32, txhash.begin());
        tx_hashes.push_back(txhash);
        pos += 32;
    }

    return true;
}

bool Share::meetsBlockTarget() const {
    auto share_hash = hash();
    return Sharechain::checkProofOfWork(share_hash, header.block_bits);
}

// ============================================================================
// Sharechain implementation
// ============================================================================

Sharechain::Sharechain() : Sharechain(Config{}) {}

Sharechain::Sharechain(const Config& config) : config_(config) {}

Sharechain::~Sharechain() {
    shutdown();
}

bool Sharechain::initialize() {
    LOG_INFO("Initializing sharechain...");

    // Create data directory
    std::filesystem::create_directories(config_.data_dir);

    // Load existing shares from disk
    if (!loadFromDisk()) {
        LOG_DEBUG("No existing sharechain found, starting fresh");

        // Create genesis share index
        auto genesis = std::make_unique<ShareIndex>();
        genesis->height = 0;
        genesis->timestamp = 1737331200;  // 2026-01-20 00:00:00 UTC
        genesis->bits = targetToBits(bitsToTarget(0x1d00ffff));  // Easy initial difficulty
        genesis->difficulty = 1;
        genesis->chain_work = 1;
        genesis->hash = P2PoolParams::mainnet().genesis_share_hash;

        tip_ = genesis.get();
        index_map_[genesis->hash] = std::move(genesis);
    }

    LOG_INFO("Sharechain initialized: height={}", getHeight());
    return true;
}

void Sharechain::shutdown() {
    // Save share index to disk
    if (!index_map_.empty()) {
        saveShareIndex();
    }

    if (current_file_.is_open()) {
        current_file_.close();
    }

    LOG_INFO("Sharechain shutdown complete");
}

bool Sharechain::loadFromDisk() {
    std::string index_path = config_.data_dir + "/shareindex.dat";

    std::ifstream index_file(index_path, std::ios::binary);
    if (!index_file) {
        return false;
    }

    uint32_t count = 0;
    index_file.read(reinterpret_cast<char*>(&count), 4);

    for (uint32_t i = 0; i < count && index_file.good(); i++) {
        auto index = std::make_unique<ShareIndex>();

        index_file.read(reinterpret_cast<char*>(index->hash.data()), 32);
        index_file.read(reinterpret_cast<char*>(index->prev_hash.data()), 32);
        index_file.read(reinterpret_cast<char*>(&index->height), 4);
        index_file.read(reinterpret_cast<char*>(&index->timestamp), 4);
        index_file.read(reinterpret_cast<char*>(&index->bits), 4);
        index_file.read(reinterpret_cast<char*>(&index->difficulty), 8);
        index_file.read(reinterpret_cast<char*>(&index->chain_work), 8);

        uint32_t script_len;
        index_file.read(reinterpret_cast<char*>(&script_len), 4);
        index->payout_script.resize(script_len);
        index_file.read(reinterpret_cast<char*>(index->payout_script.data()), script_len);

        index_file.read(reinterpret_cast<char*>(&index->payout_weight), 8);
        index_file.read(reinterpret_cast<char*>(&index->file_num), 4);
        index_file.read(reinterpret_cast<char*>(&index->file_pos), 4);

        index_map_[index->hash] = std::move(index);
    }

    // Link indices
    ShareIndex* best_tip = nullptr;
    uint64_t best_work = 0;

    for (auto& [hash, index] : index_map_) {
        if (!isZeroHash(index->prev_hash)) {
            auto it = index_map_.find(index->prev_hash);
            if (it != index_map_.end()) {
                index->prev = it->second.get();
            }
        }

        if (index->chain_work > best_work) {
            best_work = index->chain_work;
            best_tip = index.get();
        }
    }

    tip_ = best_tip;

    LOG_INFO("Loaded {} share indices from disk", index_map_.size());
    return !index_map_.empty();
}

bool Sharechain::saveShareIndex() {
    std::string index_path = config_.data_dir + "/shareindex.dat";

    std::ofstream file(index_path, std::ios::binary);
    if (!file) {
        LOG_ERROR("Failed to open share index for writing: {}", index_path);
        return false;
    }

    uint32_t count = static_cast<uint32_t>(index_map_.size());
    file.write(reinterpret_cast<const char*>(&count), 4);

    for (const auto& [hash, index] : index_map_) {
        file.write(reinterpret_cast<const char*>(index->hash.data()), 32);
        file.write(reinterpret_cast<const char*>(index->prev_hash.data()), 32);
        file.write(reinterpret_cast<const char*>(&index->height), 4);
        file.write(reinterpret_cast<const char*>(&index->timestamp), 4);
        file.write(reinterpret_cast<const char*>(&index->bits), 4);
        file.write(reinterpret_cast<const char*>(&index->difficulty), 8);
        file.write(reinterpret_cast<const char*>(&index->chain_work), 8);

        uint32_t script_len = static_cast<uint32_t>(index->payout_script.size());
        file.write(reinterpret_cast<const char*>(&script_len), 4);
        file.write(reinterpret_cast<const char*>(index->payout_script.data()), script_len);

        file.write(reinterpret_cast<const char*>(&index->payout_weight), 8);
        file.write(reinterpret_cast<const char*>(&index->file_num), 4);
        file.write(reinterpret_cast<const char*>(&index->file_pos), 4);
    }

    file.flush();
    LOG_INFO("Saved {} share indices to disk", count);
    return file.good();
}

bool Sharechain::saveShare(const Share& share) {
    // Open file if needed
    if (!current_file_.is_open()) {
        std::string path = getShareFilePath(current_file_num_);
        current_file_.open(path, std::ios::binary | std::ios::app);
        if (!current_file_) {
            LOG_ERROR("Failed to open share file: {}", path);
            return false;
        }
    }

    // Check file size, rotate if needed (100MB max)
    current_file_.seekp(0, std::ios::end);
    if (current_file_.tellp() > 100 * 1024 * 1024) {
        current_file_.close();
        current_file_num_++;
        std::string path = getShareFilePath(current_file_num_);
        current_file_.open(path, std::ios::binary | std::ios::app);
    }

    auto data = share.serialize();
    uint32_t len = data.size();

    current_file_.write(reinterpret_cast<const char*>(&len), 4);
    current_file_.write(reinterpret_cast<const char*>(data.data()), data.size());
    current_file_.flush();

    return true;
}

std::string Sharechain::getShareFilePath(int file_num) const {
    return config_.data_dir + "/shares" + std::to_string(file_num) + ".dat";
}

bool Sharechain::processShare(const Share& share, std::string& error) {
    stats_received_++;

    crypto::Hash256 hash = share.hash();

    LOG_DEBUG("Processing share {}", hashToHex(hash).substr(0, 16));

    // Check if we already have it
    {
        std::lock_guard<std::mutex> lock(index_mutex_);
        if (index_map_.count(hash) > 0) {
            error = "duplicate share";
            return false;
        }
    }

    // Validate share
    if (!checkShare(share, error)) {
        stats_rejected_++;
        LOG_DEBUG("Share rejected: {}", error);
        return false;
    }

    // Check PoW
    if (!checkSharePoW(share)) {
        stats_rejected_++;
        error = "insufficient proof of work";
        LOG_DEBUG("Share rejected: {}", error);
        return false;
    }

    // Find previous share
    ShareIndex* prev = nullptr;
    {
        std::lock_guard<std::mutex> lock(index_mutex_);
        auto it = index_map_.find(share.header.prev_share);
        if (it != index_map_.end()) {
            prev = it->second.get();
        }
    }

    if (!prev && !isZeroHash(share.header.prev_share)) {
        // Orphan share - save for later
        addOrphanShare(share);
        error = "orphan share (missing parent)";
        return false;
    }

    // Connect share
    if (!connectShare(share, prev)) {
        stats_rejected_++;
        error = "failed to connect share";
        return false;
    }

    stats_accepted_++;

    // Record timing for share rate calculation
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        auto now = std::chrono::steady_clock::now();
        recent_shares_.push_back(now);

        // Keep only last 100 shares for rate calculation
        while (recent_shares_.size() > 100) {
            recent_shares_.pop_front();
        }
        last_share_time_ = now;
    }

    // Check for orphans that can now be processed
    processOrphanShares(hash);

    // Notify callback
    if (on_share_) {
        on_share_(share, true);
    }

    // Check if this share meets main chain target
    if (share.meetsBlockTarget()) {
        LOG_NOTICE("Share {} meets block target! Submitting to main chain...",
                   hashToHex(hash).substr(0, 16));
        stats_blocks_++;

        // Build and submit block
        if (on_new_block_) {
            chain::Block block;
            block.header.version = 1;
            block.header.prev_hash = share.header.block_prev_hash;
            block.header.merkle_root = share.header.merkle_root;
            block.header.timestamp = share.header.timestamp;
            block.header.bits = share.header.block_bits;
            block.header.nonce = share.header.nonce;
            block.transactions.push_back(share.generation_tx);

            // Add other transactions (would need to fetch from mempool)

            on_new_block_(block);
        }
    }

    return true;
}

bool Sharechain::connectShare(const Share& share, ShareIndex* prev) {
    std::lock_guard<std::mutex> lock(index_mutex_);

    auto index = std::make_unique<ShareIndex>();
    index->hash = share.hash();
    index->prev_hash = share.header.prev_share;
    index->height = prev ? prev->height + 1 : 0;
    index->timestamp = share.header.timestamp;
    index->bits = share.header.bits;
    index->difficulty = share.getDifficulty();
    index->chain_work = (prev ? prev->chain_work : 0) + index->difficulty;
    index->prev = prev;

    // Store first payout script
    if (!share.payouts.empty()) {
        index->payout_script = share.payouts[0].script_pubkey;
        index->payout_weight = share.payouts[0].weight;
    }

    // Save to disk
    if (!saveShare(share)) {
        LOG_ERROR("Failed to save share to disk");
        return false;
    }

    index->file_num = current_file_num_;
    current_file_.seekp(0, std::ios::end);
    index->file_pos = static_cast<uint32_t>(current_file_.tellp()) - share.serialize().size() - 4;

    ShareIndex* new_index = index.get();
    index_map_[index->hash] = std::move(index);

    // Update tip if this is the best chain
    if (!tip_ || new_index->chain_work > tip_->chain_work) {
        updateTip(new_index);
    }

    LOG_DEBUG("Share connected: height={} work={}",
              new_index->height, new_index->chain_work);

    return true;
}

void Sharechain::updateTip(ShareIndex* new_tip) {
    if (tip_ != new_tip) {
        LOG_INFO("New sharechain tip: height={} hash={}",
                 new_tip->height, hashToHex(new_tip->hash).substr(0, 16));
        tip_ = new_tip;
    }
}

std::optional<Share> Sharechain::getShare(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    auto it = index_map_.find(hash);
    if (it == index_map_.end()) {
        return std::nullopt;
    }

    ShareIndex* index = it->second.get();

    // Load from file
    std::ifstream file(getShareFilePath(index->file_num), std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    file.seekg(index->file_pos);

    uint32_t len;
    file.read(reinterpret_cast<char*>(&len), 4);

    std::vector<uint8_t> data(len);
    file.read(reinterpret_cast<char*>(data.data()), len);

    Share share;
    if (!share.deserialize(data)) {
        return std::nullopt;
    }

    return share;
}

ShareIndex* Sharechain::getShareIndex(const crypto::Hash256& hash) const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    auto it = index_map_.find(hash);
    return it != index_map_.end() ? it->second.get() : nullptr;
}

bool Sharechain::checkShareHeader(const ShareHeader& header, std::string& error) const {
    // Version check
    if (header.version < 1 || header.version > 2) {
        error = "invalid share version";
        return false;
    }

    // Timestamp sanity check
    uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    if (header.timestamp > now + 7200) {  // 2 hours in future
        error = "share timestamp too far in future";
        return false;
    }

    // Check difficulty bits format
    uint32_t exp = header.bits >> 24;
    if (exp > 32 || exp < 3) {
        error = "invalid difficulty bits";
        return false;
    }

    return true;
}

bool Sharechain::checkShare(const Share& share, std::string& error) const {
    // Check header
    if (!checkShareHeader(share.header, error)) {
        return false;
    }

    // Must have at least one payout
    if (share.payouts.empty()) {
        error = "share has no payouts";
        return false;
    }

    // Validate payout scripts
    for (const auto& payout : share.payouts) {
        if (payout.script_pubkey.empty() || payout.script_pubkey.size() > 10000) {
            error = "invalid payout script";
            return false;
        }
        if (payout.weight == 0) {
            error = "zero payout weight";
            return false;
        }
    }

    // Validate generation transaction
    if (share.generation_tx.inputs.empty()) {
        error = "generation tx has no inputs";
        return false;
    }

    return true;
}

bool Sharechain::checkSharePoW(const Share& share) const {
    auto hash = share.hash();
    return checkProofOfWork(hash, share.header.bits);
}

bool Sharechain::checkProofOfWork(const crypto::Hash256& hash, uint32_t bits) {
    crypto::Hash256 target = bitsToTarget(bits);

    // Compare hash <= target (little-endian comparison)
    for (int i = 31; i >= 0; i--) {
        if (hash[i] < target[i]) return true;
        if (hash[i] > target[i]) return false;
    }
    return true;  // Equal
}

crypto::Hash256 Sharechain::bitsToTarget(uint32_t bits) {
    crypto::Hash256 target;
    target.fill(0);

    uint32_t exp = bits >> 24;
    uint32_t mantissa = bits & 0x00FFFFFF;

    if (exp <= 3) {
        mantissa >>= 8 * (3 - exp);
        target[0] = mantissa & 0xFF;
        target[1] = (mantissa >> 8) & 0xFF;
        target[2] = (mantissa >> 16) & 0xFF;
    } else {
        int start = exp - 3;
        if (start < 32) {
            target[start] = mantissa & 0xFF;
            if (start + 1 < 32) target[start + 1] = (mantissa >> 8) & 0xFF;
            if (start + 2 < 32) target[start + 2] = (mantissa >> 16) & 0xFF;
        }
    }

    return target;
}

uint32_t Sharechain::targetToBits(const crypto::Hash256& target) {
    // Find highest non-zero byte
    int exp = 32;
    for (int i = 31; i >= 0; i--) {
        if (target[i] != 0) {
            exp = i + 1;
            break;
        }
    }

    uint32_t mantissa = 0;
    if (exp >= 3) {
        mantissa = target[exp - 1] | (target[exp - 2] << 8) | (target[exp - 3] << 16);
    } else {
        mantissa = target[0];
        for (int i = 1; i < exp; i++) {
            mantissa |= target[i] << (i * 8);
        }
    }

    // Handle negative (first bit set)
    if (mantissa & 0x00800000) {
        mantissa >>= 8;
        exp++;
    }

    return (exp << 24) | (mantissa & 0x00FFFFFF);
}

uint32_t Sharechain::getNextShareDifficulty() const {
    return calculateNextDifficulty(tip_);
}

uint32_t Sharechain::calculateNextDifficulty(const ShareIndex* tip) const {
    if (!tip || tip->height < 360) {
        return config_.min_difficulty;
    }

    // Get share from 360 shares ago
    const ShareIndex* first = tip;
    for (uint32_t i = 0; i < 360 && first->prev; i++) {
        first = first->prev;
    }

    // Calculate actual time span
    int64_t actual_timespan = tip->timestamp - first->timestamp;
    int64_t target_timespan = 360 * config_.target_spacing;  // 360 * 30 = 10800 seconds

    // Limit adjustment
    if (actual_timespan < target_timespan / 4) {
        actual_timespan = target_timespan / 4;
    }
    if (actual_timespan > target_timespan * 4) {
        actual_timespan = target_timespan * 4;
    }

    // Calculate new target
    crypto::Hash256 current_target = bitsToTarget(tip->bits);

    // Multiply by actual_timespan / target_timespan
    // Simplified: use difficulty value
    uint64_t new_difficulty = tip->difficulty * target_timespan / actual_timespan;

    if (new_difficulty < config_.min_difficulty) {
        new_difficulty = config_.min_difficulty;
    }

    // Convert back to bits (simplified)
    return targetToBits(bitsToTarget(static_cast<uint32_t>(new_difficulty)));
}

uint32_t Sharechain::getShareTarget() const {
    return tip_ ? tip_->bits : config_.min_difficulty;
}

void Sharechain::addOrphanShare(const Share& share) {
    std::lock_guard<std::mutex> lock(orphan_mutex_);

    crypto::Hash256 hash = share.hash();

    // Check limit
    if (orphan_shares_.size() >= 1000) {
        // Remove oldest orphan
        auto it = orphan_shares_.begin();
        orphan_by_prev_.erase(it->second.header.prev_share);
        orphan_shares_.erase(it);
    }

    orphan_shares_[hash] = share;
    orphan_by_prev_.insert({share.header.prev_share, hash});

    LOG_DEBUG("Added orphan share {} (parent: {})",
              hashToHex(hash).substr(0, 16),
              hashToHex(share.header.prev_share).substr(0, 16));
}

void Sharechain::processOrphanShares(const crypto::Hash256& prev_hash) {
    std::lock_guard<std::mutex> lock(orphan_mutex_);

    auto range = orphan_by_prev_.equal_range(prev_hash);
    std::vector<crypto::Hash256> to_process;

    for (auto it = range.first; it != range.second; ++it) {
        to_process.push_back(it->second);
    }

    for (const auto& hash : to_process) {
        auto it = orphan_shares_.find(hash);
        if (it != orphan_shares_.end()) {
            Share share = std::move(it->second);
            orphan_shares_.erase(it);
            orphan_by_prev_.erase(prev_hash);

            // Try to process (releases lock, so be careful)
            std::string error;
            orphan_mutex_.unlock();
            processShare(share, error);
            orphan_mutex_.lock();
        }
    }
}

std::vector<ShareIndex*> Sharechain::getPPLNSWindow() const {
    std::lock_guard<std::mutex> lock(index_mutex_);

    std::vector<ShareIndex*> window;
    window.reserve(config_.pplns_window);

    ShareIndex* current = tip_;
    while (current && window.size() < config_.pplns_window) {
        window.push_back(current);
        current = current->prev;
    }

    return window;
}

std::map<std::vector<uint8_t>, uint64_t> Sharechain::calculatePayouts(uint64_t reward) const {
    std::map<std::vector<uint8_t>, uint64_t> payouts;

    auto window = getPPLNSWindow();
    if (window.empty()) {
        return payouts;
    }

    // Sum total work in window
    uint64_t total_work = 0;
    for (const auto* share : window) {
        total_work += share->payout_weight > 0 ? share->payout_weight : share->difficulty;
    }

    if (total_work == 0) {
        return payouts;
    }

    // Calculate share of reward for each participant
    for (const auto* share : window) {
        if (share->payout_script.empty()) continue;

        uint64_t work = share->payout_weight > 0 ? share->payout_weight : share->difficulty;
        uint64_t payout = reward * work / total_work;

        if (payout > 0) {
            payouts[share->payout_script] += payout;
        }
    }

    return payouts;
}

chain::Transaction Sharechain::buildGenerationTx(
    const std::vector<uint8_t>& pool_script,
    uint64_t block_reward,
    uint64_t fees
) const {
    chain::Transaction tx;
    tx.version = 1;
    tx.locktime = 0;

    // Coinbase input
    chain::TxInput coinbase_input;
    coinbase_input.prevout.txid.fill(0);
    coinbase_input.prevout.index = 0xFFFFFFFF;

    // Coinbase script: height + extra nonce
    uint32_t height = tip_ ? tip_->height + 1 : 0;
    coinbase_input.script_sig.push_back(3);  // Push 3 bytes
    coinbase_input.script_sig.push_back(height & 0xFF);
    coinbase_input.script_sig.push_back((height >> 8) & 0xFF);
    coinbase_input.script_sig.push_back((height >> 16) & 0xFF);

    // Add P2Pool marker
    std::string marker = "/FTC P2Pool/";
    coinbase_input.script_sig.insert(
        coinbase_input.script_sig.end(),
        marker.begin(), marker.end()
    );

    tx.inputs.push_back(coinbase_input);

    // Calculate payouts
    uint64_t total_reward = block_reward + fees;
    auto payouts = calculatePayouts(total_reward);

    // Create outputs for each participant
    for (const auto& [script, amount] : payouts) {
        chain::TxOutput output;
        output.value = amount;
        output.script_pubkey = script;
        tx.outputs.push_back(output);
    }

    // If no payouts (unlikely), send to pool script
    if (tx.outputs.empty()) {
        chain::TxOutput output;
        output.value = total_reward;
        output.script_pubkey = pool_script;
        tx.outputs.push_back(output);
    }

    return tx;
}

Sharechain::Stats Sharechain::getStats() const {
    Stats stats;
    stats.shares_received = stats_received_.load();
    stats.shares_accepted = stats_accepted_.load();
    stats.shares_rejected = stats_rejected_.load();
    stats.blocks_found = stats_blocks_.load();

    {
        std::lock_guard<std::mutex> lock(orphan_mutex_);
        stats.orphans = orphan_shares_.size();
    }

    // Calculate share rate
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (recent_shares_.size() >= 2) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                recent_shares_.back() - recent_shares_.front()
            ).count();
            if (duration > 0) {
                stats.share_rate = (recent_shares_.size() - 1) * 60.0 / duration;
            }
        }
    }

    return stats;
}

// ============================================================================
// ShareBuilder implementation
// ============================================================================

ShareBuilder::ShareBuilder(Sharechain* sharechain, chain::Chain* mainchain)
    : sharechain_(sharechain), mainchain_(mainchain) {}

Share ShareBuilder::buildShareTemplate(
    const std::vector<uint8_t>& payout_script,
    const std::vector<chain::Transaction>& txs,
    uint64_t block_reward,
    uint64_t fees
) const {
    Share share;

    // Header
    share.header.version = 1;
    share.header.prev_share = sharechain_->getTipHash();
    share.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    share.header.bits = sharechain_->getNextShareDifficulty();
    share.header.nonce = 0;

    // Main chain info
    if (mainchain_) {
        auto tip = mainchain_->getTip();
        if (tip) {
            share.header.block_prev_hash = tip->hash;
            share.header.block_height = tip->height + 1;
            share.header.block_bits = mainchain_->getNextWorkRequired(tip);
        }
    }

    // Payout entry for this miner
    Share::PayoutEntry entry;
    entry.script_pubkey = payout_script;
    entry.weight = chain::Consensus::getDifficulty(share.header.bits);
    share.payouts.push_back(entry);

    // Build generation transaction
    share.generation_tx = sharechain_->buildGenerationTx(
        payout_script, block_reward, fees
    );

    // Transaction hashes
    share.tx_hashes.reserve(txs.size());
    for (const auto& tx : txs) {
        share.tx_hashes.push_back(tx.getTxId());
    }

    // Compute merkle root
    std::vector<crypto::Hash256> merkle_leaves;
    merkle_leaves.push_back(share.generation_tx.getTxId());
    for (const auto& h : share.tx_hashes) {
        merkle_leaves.push_back(h);
    }
    share.header.merkle_root = chain::Consensus::computeMerkleRoot(merkle_leaves);

    return share;
}

bool ShareBuilder::validateShare(const Share& share, std::string& error) const {
    return sharechain_->checkShare(share, error);
}

bool ShareBuilder::submitShare(const Share& share, std::string& error) {
    return sharechain_->processShare(share, error);
}

bool ShareBuilder::meetsBlockTarget(const Share& share) const {
    return share.meetsBlockTarget();
}

// ============================================================================
// P2PoolParams implementation
// ============================================================================

P2PoolParams P2PoolParams::mainnet() {
    P2PoolParams params;
    params.share_target_spacing = 30;
    params.share_adjustment_interval = 360;
    params.pplns_window_size = 8640;
    params.min_pplns_window = 720;
    params.min_share_difficulty = 1;
    params.max_share_difficulty = 0x1d00ffff;
    params.min_payout = 10000;
    params.payout_maturity = 100;
    params.p2pool_port = 17320;

    // Genesis share hash (deterministic)
    std::string genesis_data = "FTC P2Pool Genesis 2026-01-20";
    params.genesis_share_hash = crypto::keccak256(
        reinterpret_cast<const uint8_t*>(genesis_data.data()),
        genesis_data.size()
    );

    return params;
}

P2PoolParams P2PoolParams::testnet() {
    P2PoolParams params = mainnet();
    params.share_target_spacing = 15;  // Faster for testing
    params.pplns_window_size = 1440;   // Shorter window
    params.min_pplns_window = 144;
    params.p2pool_port = 27320;
    return params;
}

} // namespace p2pool
} // namespace ftc
