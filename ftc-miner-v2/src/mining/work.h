#ifndef FTC_MINER_MINING_WORK_H
#define FTC_MINER_MINING_WORK_H

#include "keccak256.h"
#include <vector>
#include <string>
#include <cstdint>
#include <mutex>
#include <atomic>

namespace mining {

// Work unit from pool/node
struct Work {
    std::string job_id;
    uint32_t height = 0;
    Hash256 prev_hash;
    Hash256 merkle_root;  // Pre-computed by node
    Hash256 target;
    uint32_t bits = 0;
    uint32_t timestamp = 0;
    uint32_t version = 1;
    std::vector<uint8_t> coinbase;
    std::vector<Hash256> merkle_branch;
    std::vector<std::string> transactions_hex;  // For block assembly

    // Build 76-byte header (without nonce)
    std::vector<uint8_t> buildHeader() const;

    // Build full block with nonce
    std::vector<uint8_t> buildBlock(uint32_t nonce) const;

    // Genesis block has height 0, so we only check bits
    bool isValid() const { return bits > 0; }
};

// Found solution
struct Solution {
    std::string job_id;
    uint32_t nonce;
    Hash256 hash;
    uint32_t height;
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

    // Submit solution
    void submitSolution(const Solution& solution);

    // Get pending solutions
    std::vector<Solution> getPendingSolutions();

private:
    mutable std::mutex work_mutex_;
    Work current_work_;
    std::atomic<bool> new_work_;

    std::mutex solutions_mutex_;
    std::vector<Solution> pending_solutions_;
};

} // namespace mining

#endif // FTC_MINER_MINING_WORK_H
