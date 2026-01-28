#include "work.h"
#include <cstring>

namespace mining {

// Helper to convert hex string to bytes
static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            byte <<= 4;
            if (c >= '0' && c <= '9') byte |= (c - '0');
            else if (c >= 'a' && c <= 'f') byte |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') byte |= (c - 'A' + 10);
        }
        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

std::vector<uint8_t> Work::buildHeader() const {
    std::vector<uint8_t> header;
    header.reserve(76);

    // Version (4 bytes, little-endian)
    header.push_back(version & 0xFF);
    header.push_back((version >> 8) & 0xFF);
    header.push_back((version >> 16) & 0xFF);
    header.push_back((version >> 24) & 0xFF);

    // Previous block hash (32 bytes)
    header.insert(header.end(), prev_hash.begin(), prev_hash.end());

    // Merkle root (32 bytes) - from node template
    header.insert(header.end(), merkle_root.begin(), merkle_root.end());

    // Timestamp (4 bytes, little-endian)
    header.push_back(timestamp & 0xFF);
    header.push_back((timestamp >> 8) & 0xFF);
    header.push_back((timestamp >> 16) & 0xFF);
    header.push_back((timestamp >> 24) & 0xFF);

    // Bits/difficulty (4 bytes, little-endian)
    header.push_back(bits & 0xFF);
    header.push_back((bits >> 8) & 0xFF);
    header.push_back((bits >> 16) & 0xFF);
    header.push_back((bits >> 24) & 0xFF);

    return header;
}

std::vector<uint8_t> Work::buildBlock(uint32_t nonce, uint32_t timestamp_offset) const {
    std::vector<uint8_t> block;

    // Header (80 bytes with nonce)
    auto header = buildHeader();

    // Apply timestamp offset if provided (bytes 68-71 are timestamp, little-endian)
    if (timestamp_offset > 0) {
        uint32_t new_ts = timestamp + timestamp_offset;
        header[68] = new_ts & 0xFF;
        header[69] = (new_ts >> 8) & 0xFF;
        header[70] = (new_ts >> 16) & 0xFF;
        header[71] = (new_ts >> 24) & 0xFF;
    }

    block.insert(block.end(), header.begin(), header.end());

    // Nonce (4 bytes, little-endian)
    block.push_back(nonce & 0xFF);
    block.push_back((nonce >> 8) & 0xFF);
    block.push_back((nonce >> 16) & 0xFF);
    block.push_back((nonce >> 24) & 0xFF);

    // Transaction count (varint)
    size_t tx_count = 1 + transactions_hex.size();  // coinbase + transactions
    if (tx_count < 0xFD) {
        block.push_back(static_cast<uint8_t>(tx_count));
    } else if (tx_count <= 0xFFFF) {
        block.push_back(0xFD);
        block.push_back(tx_count & 0xFF);
        block.push_back((tx_count >> 8) & 0xFF);
    } else {
        block.push_back(0xFE);
        block.push_back(tx_count & 0xFF);
        block.push_back((tx_count >> 8) & 0xFF);
        block.push_back((tx_count >> 16) & 0xFF);
        block.push_back((tx_count >> 24) & 0xFF);
    }

    // Coinbase transaction
    block.insert(block.end(), coinbase.begin(), coinbase.end());

    // Other transactions
    for (const auto& tx_hex : transactions_hex) {
        auto tx_bytes = hexToBytes(tx_hex);
        block.insert(block.end(), tx_bytes.begin(), tx_bytes.end());
    }

    return block;
}

WorkManager::WorkManager()
    : new_work_(false)
{}

void WorkManager::setWork(const Work& work) {
    std::lock_guard<std::mutex> lock(work_mutex_);
    current_work_ = work;
    new_work_ = true;
}

Work WorkManager::getWork() const {
    std::lock_guard<std::mutex> lock(work_mutex_);
    return current_work_;
}

bool WorkManager::hasWork() const {
    std::lock_guard<std::mutex> lock(work_mutex_);
    return current_work_.isValid();
}

void WorkManager::submitSolution(const Solution& solution) {
    {
        std::lock_guard<std::mutex> lock(solutions_mutex_);
        pending_solutions_.push_back(solution);
    }
    // Notify waiting threads IMMEDIATELY - this is the key to adaptive submission
    solutions_cv_.notify_one();
}

std::vector<Solution> WorkManager::getPendingSolutions() {
    std::lock_guard<std::mutex> lock(solutions_mutex_);
    std::vector<Solution> result;
    result.swap(pending_solutions_);
    return result;
}

std::optional<Solution> WorkManager::getOneSolution() {
    std::lock_guard<std::mutex> lock(solutions_mutex_);
    if (pending_solutions_.empty()) {
        return std::nullopt;
    }
    Solution sol = std::move(pending_solutions_.front());
    pending_solutions_.erase(pending_solutions_.begin());
    return sol;
}

size_t WorkManager::clearPendingSolutions() {
    std::lock_guard<std::mutex> lock(solutions_mutex_);
    size_t count = pending_solutions_.size();
    pending_solutions_.clear();
    return count;
}

bool WorkManager::waitForSolutions(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(solutions_mutex_);
    // Wait until we have solutions OR timeout
    // This is ADAPTIVE - wakes up IMMEDIATELY when solutions arrive
    // No fixed polling interval - responds to actual events
    return solutions_cv_.wait_for(lock, timeout, [this]() {
        return !pending_solutions_.empty();
    });
}

size_t WorkManager::getPendingCount() const {
    std::lock_guard<std::mutex> lock(solutions_mutex_);
    return pending_solutions_.size();
}

} // namespace mining
