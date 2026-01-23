#ifndef FTC_P2POOL_SHARECHAIN_H
#define FTC_P2POOL_SHARECHAIN_H

#include "crypto/keccak256.h"
#include "chain/transaction.h"
#include "chain/block.h"
#include "chain/chain.h"

#include <vector>
#include <map>
#include <set>
#include <deque>
#include <mutex>
#include <memory>
#include <functional>
#include <fstream>
#include <chrono>
#include <atomic>

namespace ftc {
namespace p2pool {

// ============================================================================
// Share - a proof of work submission to P2Pool
// ============================================================================

/**
 * Share represents a proof-of-work submission that meets the P2Pool
 * difficulty target (lower than main chain difficulty).
 *
 * Structure:
 * - Header: Similar to block header but with P2Pool-specific data
 * - Payout script: Who gets paid for this share
 * - Previous shares: Links to recent shares for PPLNS
 */
struct ShareHeader {
    uint32_t version;                   // Share version
    crypto::Hash256 prev_share;         // Previous share in sharechain
    crypto::Hash256 merkle_root;        // Merkle root of payout data
    uint32_t timestamp;                 // Share timestamp
    uint32_t bits;                      // Share difficulty target
    uint32_t nonce;                     // Nonce for share PoW

    // Block template data
    crypto::Hash256 block_prev_hash;    // Main chain prev block
    uint32_t block_height;              // Target main chain height
    uint32_t block_bits;                // Main chain difficulty

    // Serialization
    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);

    // Hash of this share header
    crypto::Hash256 hash() const;
};

struct Share {
    ShareHeader header;

    // Payout information
    struct PayoutEntry {
        std::vector<uint8_t> script_pubkey;  // Destination script
        uint64_t weight;                      // Share weight (difficulty)
    };
    std::vector<PayoutEntry> payouts;

    // Generation transaction for the block template
    chain::Transaction generation_tx;

    // Other transactions in the block template
    std::vector<crypto::Hash256> tx_hashes;

    // Computed fields
    crypto::Hash256 hash() const { return header.hash(); }
    uint64_t getDifficulty() const;

    // Serialization
    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);

    // Check if this share would be valid as a main chain block
    bool meetsBlockTarget() const;
};

// ============================================================================
// ShareIndex - index entry for sharechain
// ============================================================================

struct ShareIndex {
    crypto::Hash256 hash;
    crypto::Hash256 prev_hash;
    uint32_t height;
    uint32_t timestamp;
    uint32_t bits;
    uint64_t difficulty;
    uint64_t chain_work;

    // For tracking payouts
    std::vector<uint8_t> payout_script;
    uint64_t payout_weight;

    // File position for loading share data
    uint32_t file_num;
    uint32_t file_pos;

    ShareIndex* prev = nullptr;
};

// ============================================================================
// Sharechain - manages the P2Pool share chain
// ============================================================================

/**
 * Sharechain maintains a separate chain of shares.
 * Shares have ~30 second target time (20x faster than main chain).
 *
 * Key features:
 * - PPLNS window: ~8640 shares (3 days of shares at 30s each)
 * - Share difficulty: Targets 30 second share time
 * - Payout calculation: Based on share contributions in PPLNS window
 */
class Sharechain {
public:
    struct Config {
        std::string data_dir = "./shares";
        uint32_t target_spacing = 30;       // 30 second target share time
        uint32_t pplns_window = 8640;       // ~3 days of shares
        uint32_t min_difficulty = 1;
        uint64_t max_chain_work = 0;        // For testnet limiting

        Config() = default;
    };

    Sharechain();
    explicit Sharechain(const Config& config);
    ~Sharechain();

    // Lifecycle
    bool initialize();
    void shutdown();

    // Share management
    bool processShare(const Share& share, std::string& error);
    std::optional<Share> getShare(const crypto::Hash256& hash) const;
    ShareIndex* getShareIndex(const crypto::Hash256& hash) const;

    // Chain state
    ShareIndex* getTip() const { return tip_; }
    uint32_t getHeight() const { return tip_ ? tip_->height : 0; }
    crypto::Hash256 getTipHash() const {
        return tip_ ? tip_->hash : crypto::Hash256{};
    }

    // Difficulty
    uint32_t getNextShareDifficulty() const;
    uint32_t getShareTarget() const;

    // PPLNS window
    std::vector<ShareIndex*> getPPLNSWindow() const;
    std::map<std::vector<uint8_t>, uint64_t> calculatePayouts(uint64_t reward) const;

    // Block building
    chain::Transaction buildGenerationTx(
        const std::vector<uint8_t>& pool_script,
        uint64_t block_reward,
        uint64_t fees
    ) const;

    // Validation
    bool checkShareHeader(const ShareHeader& header, std::string& error) const;
    bool checkShare(const Share& share, std::string& error) const;
    bool checkSharePoW(const Share& share) const;

    // Orphan management
    void addOrphanShare(const Share& share);
    void processOrphanShares(const crypto::Hash256& prev_hash);

    // Callbacks
    using ShareCallback = std::function<void(const Share&, bool accepted)>;
    void setShareCallback(ShareCallback cb) { on_share_ = cb; }

    using NewBlockCallback = std::function<void(const chain::Block&)>;
    void setNewBlockCallback(NewBlockCallback cb) { on_new_block_ = cb; }

    // Statistics
    struct Stats {
        uint64_t shares_received = 0;
        uint64_t shares_accepted = 0;
        uint64_t shares_rejected = 0;
        uint64_t orphans = 0;
        uint64_t blocks_found = 0;
        double share_rate = 0.0;  // Shares per minute
    };
    Stats getStats() const;

    // Static helper methods for difficulty
    static crypto::Hash256 bitsToTarget(uint32_t bits);
    static uint32_t targetToBits(const crypto::Hash256& target);
    static bool checkProofOfWork(const crypto::Hash256& hash, uint32_t bits);

private:
    Config config_;

    // Index storage
    std::map<crypto::Hash256, std::unique_ptr<ShareIndex>> index_map_;
    mutable std::mutex index_mutex_;

    // Tip of sharechain
    ShareIndex* tip_ = nullptr;

    // Orphan shares (waiting for parent)
    std::map<crypto::Hash256, Share> orphan_shares_;
    std::multimap<crypto::Hash256, crypto::Hash256> orphan_by_prev_;
    mutable std::mutex orphan_mutex_;

    // File storage
    int current_file_num_ = 0;
    std::fstream current_file_;
    std::string getShareFilePath(int file_num) const;

    // Callbacks
    ShareCallback on_share_;
    NewBlockCallback on_new_block_;

    // Statistics
    mutable std::atomic<uint64_t> stats_received_{0};
    mutable std::atomic<uint64_t> stats_accepted_{0};
    mutable std::atomic<uint64_t> stats_rejected_{0};
    mutable std::atomic<uint64_t> stats_blocks_{0};
    std::chrono::steady_clock::time_point last_share_time_;
    std::deque<std::chrono::steady_clock::time_point> recent_shares_;
    mutable std::mutex stats_mutex_;

    // Internal methods
    bool loadFromDisk();
    bool saveShareIndex();
    bool saveShare(const Share& share);
    bool connectShare(const Share& share, ShareIndex* prev);
    void updateTip(ShareIndex* new_tip);

    // Difficulty calculation
    uint32_t calculateNextDifficulty(const ShareIndex* tip) const;
};

// ============================================================================
// ShareBuilder - builds shares for miners
// ============================================================================

class ShareBuilder {
public:
    ShareBuilder(Sharechain* sharechain, chain::Chain* mainchain);

    // Build a share template for mining
    Share buildShareTemplate(
        const std::vector<uint8_t>& payout_script,
        const std::vector<chain::Transaction>& txs,
        uint64_t block_reward,
        uint64_t fees
    ) const;

    // Check if a completed share is valid
    bool validateShare(const Share& share, std::string& error) const;

    // Submit a mined share
    bool submitShare(const Share& share, std::string& error);

    // Check if share meets main chain target
    bool meetsBlockTarget(const Share& share) const;

private:
    Sharechain* sharechain_;
    chain::Chain* mainchain_;
};

// ============================================================================
// P2Pool Consensus Parameters
// ============================================================================

struct P2PoolParams {
    // Share timing
    uint32_t share_target_spacing = 30;        // 30 second target
    uint32_t share_adjustment_interval = 360;  // Adjust every ~3 hours

    // PPLNS parameters
    uint32_t pplns_window_size = 8640;         // ~3 days at 30s
    uint32_t min_pplns_window = 720;           // Minimum ~6 hours

    // Share difficulty limits
    uint32_t min_share_difficulty = 1;
    uint32_t max_share_difficulty = 0x1d00ffff;

    // Payout rules
    uint64_t min_payout = 10000;               // 0.0001 FTC minimum payout
    uint32_t payout_maturity = 100;            // Wait 100 main chain blocks

    // Network
    uint16_t p2pool_port = 17320;              // P2Pool P2P port

    // Genesis share (can be computed deterministically)
    crypto::Hash256 genesis_share_hash;

    // Default mainnet parameters
    static P2PoolParams mainnet();
    static P2PoolParams testnet();
};

} // namespace p2pool
} // namespace ftc

#endif // FTC_P2POOL_SHARECHAIN_H
