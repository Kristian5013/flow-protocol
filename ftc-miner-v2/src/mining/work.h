#ifndef FTC_MINER_MINING_WORK_H
#define FTC_MINER_MINING_WORK_H

#include "keccak256.h"
#include <vector>
#include <string>
#include <cstdint>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <optional>

namespace mining {

// Work unit from pool/node
struct Work {
    std::string job_id;
    uint32_t height = 0;
    Hash256 prev_hash;
    Hash256 merkle_root;  // Pre-computed by node
    Hash256 target;        // Block target (harder)
    Hash256 share_target;  // Share target (easier, for P2Pool)
    uint32_t bits = 0;     // Block difficulty bits
    uint32_t share_bits = 0; // Share difficulty bits (P2Pool)
    uint32_t timestamp = 0;
    uint32_t version = 1;
    std::vector<uint8_t> coinbase;
    std::vector<Hash256> merkle_branch;
    std::vector<std::string> transactions_hex;  // For block assembly

    // Build 76-byte header (without nonce)
    std::vector<uint8_t> buildHeader() const;

    // Build full block with nonce and optional timestamp offset
    std::vector<uint8_t> buildBlock(uint32_t nonce, uint32_t timestamp_offset = 0) const;

    // Genesis block has height 0, so we only check bits
    bool isValid() const { return bits > 0; }
};

// Found solution
struct Solution {
    std::string job_id;
    uint32_t nonce;
    Hash256 hash;
    uint32_t height;
    uint32_t timestamp_offset = 0;  // Added to original timestamp when nonce space exhausted
    Work work;  // Work that was used to find this solution
};

// Work manager
class WorkManager {
public:
    WorkManager();

    // Set new work
    void setWork(const Work& work);

    // Get current work (thread-safe copy)
    Work getWork() const;

    // Check if we have valid work
    bool hasWork() const;

    // Signal that new work is available
    bool isNewWork() const { return new_work_.load(); }
    void clearNewWork() { new_work_ = false; }

    // Submit solution (notifies waiting threads immediately)
    void submitSolution(const Solution& solution);

    // Get pending solutions (all at once)
    std::vector<Solution> getPendingSolutions();

    // Get ONE solution (for immediate processing)
    std::optional<Solution> getOneSolution();

    // Wait for solutions (event-driven, adaptive)
    // Returns true if there are solutions, false if timeout
    // Timeout adapts based on system conditions
    bool waitForSolutions(std::chrono::milliseconds timeout = std::chrono::milliseconds(100));

    // Get count of pending solutions
    size_t getPendingCount() const;

    // Clear all pending solutions (when work changes)
    size_t clearPendingSolutions();

private:
    mutable std::mutex work_mutex_;
    Work current_work_;
    std::atomic<bool> new_work_;

    mutable std::mutex solutions_mutex_;
    std::vector<Solution> pending_solutions_;
    std::condition_variable solutions_cv_;  // Notify when solutions submitted
};

} // namespace mining

#endif // FTC_MINER_MINING_WORK_H
