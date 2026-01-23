#ifndef FTC_CHAIN_CONSENSUS_H
#define FTC_CHAIN_CONSENSUS_H

#include "chain/block.h"
#include "chain/transaction.h"
#include "chain/utxo_set.h"
#include "chain/validation.h"
#include "script/interpreter.h"
#include "crypto/keccak256.h"

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <optional>

namespace ftc {
namespace chain {

// Forward declarations
class Chain;

//-----------------------------------------------------------------------------
// Consensus Parameters
//-----------------------------------------------------------------------------

struct ConsensusParams {
    // Genesis block
    crypto::Hash256 genesis_hash;

    // Proof of work
    uint32_t pow_limit_bits;                    // Minimum difficulty (highest target)
    crypto::Hash256 pow_limit;                  // Maximum allowed target

    // Block timing
    uint32_t target_spacing;                    // Target seconds between blocks
    uint32_t target_timespan;                   // Target timespan for difficulty adjustment
    uint32_t difficulty_adjustment_interval;   // Blocks between difficulty adjustments

    // Rewards
    uint64_t initial_reward;                    // Initial block reward in satoshis
    uint32_t halving_interval;                  // Blocks between reward halvings
    uint64_t max_money;                         // Maximum total supply

    // Block limits
    size_t max_block_size;                      // Maximum block size in bytes
    size_t max_block_sigops;                    // Maximum signature operations
    size_t max_block_weight;                    // Maximum block weight (for segwit)

    // Transaction limits
    size_t max_tx_size;                         // Maximum transaction size
    uint32_t max_tx_sigops;                     // Maximum tx signature operations

    // Script flags
    uint32_t mandatory_script_flags;            // Always enforced script flags
    uint32_t standard_script_flags;             // Standard script flags

    // Softfork activation heights
    uint64_t bip16_height;                      // P2SH activation
    uint64_t bip34_height;                      // Height in coinbase
    uint64_t bip65_height;                      // CHECKLOCKTIMEVERIFY
    uint64_t bip66_height;                      // Strict DER signatures
    uint64_t bip68_height;                      // Sequence locks
    uint64_t segwit_height;                     // Segregated witness

    // Coinbase maturity
    uint32_t coinbase_maturity;                 // Blocks before coinbase can be spent

    // Default constructor with FTC mainnet parameters
    ConsensusParams();

    // Get testnet parameters
    static ConsensusParams testnet();

    // Calculate block reward at given height
    uint64_t getBlockReward(uint64_t height) const;

    // Check if height is at difficulty adjustment boundary
    bool isDifficultyAdjustment(uint64_t height) const;
};

// ValidationResult and ValidationState are defined in chain/validation.h

//-----------------------------------------------------------------------------
// Block Validation Context
//-----------------------------------------------------------------------------

struct BlockValidationContext {
    const Block* block = nullptr;
    uint64_t height = 0;
    crypto::Hash256 prev_hash;
    uint32_t prev_time = 0;
    uint32_t prev_bits = 0;
    uint64_t prev_chain_work = 0;

    // Median time past (for BIP113)
    uint32_t median_time_past = 0;

    // BIP34 check
    bool bip34_active = false;

    // Flags for script verification
    uint32_t script_flags = 0;

    // UTXO view for validation
    UTXOSet* utxo_view = nullptr;
};

//-----------------------------------------------------------------------------
// Transaction Validation Context
//-----------------------------------------------------------------------------

struct TxValidationContext {
    const Transaction* tx = nullptr;
    uint64_t block_height = 0;
    uint32_t block_time = 0;
    bool is_coinbase = false;

    // Inputs for validation
    std::vector<std::pair<Outpoint, TxOutput>> spent_outputs;

    // Flags for script verification
    uint32_t script_flags = 0;
};

//-----------------------------------------------------------------------------
// Consensus - validation engine
//-----------------------------------------------------------------------------

/**
 * Consensus - implements all FTC consensus rules
 *
 * This class provides complete block and transaction validation
 * following Bitcoin's consensus rules adapted for FTC:
 *
 * - Proof of work validation (Keccak-256)
 * - Difficulty adjustment
 * - Block structure validation
 * - Transaction validation
 * - Script execution and verification
 * - UTXO validation
 * - Coinbase validation
 */
class Consensus {
public:
    explicit Consensus(const ConsensusParams& params = ConsensusParams{});

    // Get consensus parameters
    const ConsensusParams& params() const { return params_; }

    //-------------------------------------------------------------------------
    // Block Validation
    //-------------------------------------------------------------------------

    // Check block header (proof of work, timestamps, etc.)
    bool checkBlockHeader(const BlockHeader& header, ValidationState& state) const;

    // Check block structure (without context)
    bool checkBlock(const Block& block, ValidationState& state) const;

    // Contextual block validation (with chain state)
    bool contextualCheckBlock(const Block& block,
                               const BlockValidationContext& ctx,
                               ValidationState& state) const;

    // Full block connection (validates and updates UTXO)
    bool connectBlock(const Block& block,
                      const BlockValidationContext& ctx,
                      UTXOSet& utxo_set,
                      ValidationState& state) const;

    // Disconnect block (reverts UTXO changes)
    bool disconnectBlock(const Block& block,
                         uint64_t height,
                         UTXOSet& utxo_set,
                         ValidationState& state) const;

    //-------------------------------------------------------------------------
    // Transaction Validation
    //-------------------------------------------------------------------------

    // Basic transaction checks (structure, not context)
    bool checkTransaction(const Transaction& tx, ValidationState& state) const;

    // Contextual transaction validation (with UTXO access)
    bool contextualCheckTransaction(const Transaction& tx,
                                     const TxValidationContext& ctx,
                                     ValidationState& state) const;

    // Validate transaction inputs (scripts)
    bool checkInputs(const Transaction& tx,
                     const std::vector<std::pair<Outpoint, TxOutput>>& inputs,
                     uint32_t flags,
                     ValidationState& state) const;

    //-------------------------------------------------------------------------
    // Proof of Work
    //-------------------------------------------------------------------------

    // Check if block hash meets target
    bool checkProofOfWork(const crypto::Hash256& hash, uint32_t bits) const;

    // Calculate next difficulty target
    uint32_t getNextWorkRequired(uint64_t height,
                                  const BlockHeader& last_header,
                                  const std::function<BlockHeader(uint64_t)>& getHeader) const;

    // Calculate chain work for a block
    crypto::Hash256 getBlockProof(const BlockHeader& header) const;

    //-------------------------------------------------------------------------
    // Coinbase Validation
    //-------------------------------------------------------------------------

    // Check coinbase transaction
    bool checkCoinbase(const Transaction& tx,
                       uint64_t height,
                       uint64_t block_reward,
                       uint64_t fees,
                       ValidationState& state) const;

    // Check if a coinbase is mature
    bool isCoinbaseMature(uint64_t coinbase_height, uint64_t spending_height) const;

    //-------------------------------------------------------------------------
    // Difficulty Utilities
    //-------------------------------------------------------------------------

    // Convert compact bits to target hash
    static crypto::Hash256 bitsToTarget(uint32_t bits);

    // Convert target hash to compact bits
    static uint32_t targetToBits(const crypto::Hash256& target);

    // Get difficulty as a double
    static double getDifficulty(uint32_t bits);

    // Compare two targets (returns <0, 0, >0)
    static int compareTargets(const crypto::Hash256& a, const crypto::Hash256& b);

    //-------------------------------------------------------------------------
    // Script Flags
    //-------------------------------------------------------------------------

    // Get script verification flags for a block at given height
    uint32_t getScriptFlags(uint64_t height) const;

    //-------------------------------------------------------------------------
    // Merkle Tree
    //-------------------------------------------------------------------------

    // Compute merkle root from transactions
    static crypto::Hash256 computeMerkleRoot(const std::vector<Transaction>& txs);

    // Compute merkle root from hashes
    static crypto::Hash256 computeMerkleRoot(const std::vector<crypto::Hash256>& hashes);

    // Verify merkle proof
    static bool verifyMerkleProof(const crypto::Hash256& txid,
                                   const crypto::Hash256& root,
                                   const std::vector<crypto::Hash256>& proof,
                                   uint32_t index);

private:
    ConsensusParams params_;

    // Internal validation helpers
    bool checkBlockSize(const Block& block, ValidationState& state) const;
    bool checkBlockWeight(const Block& block, ValidationState& state) const;
    bool checkDuplicateTxids(const Block& block, ValidationState& state) const;
    bool checkMerkleRoot(const Block& block, ValidationState& state) const;

    bool checkTxStructure(const Transaction& tx, ValidationState& state) const;
    bool checkTxInputs(const Transaction& tx, ValidationState& state) const;
    bool checkTxOutputs(const Transaction& tx, ValidationState& state) const;

    bool verifyScript(const ftc::script::Script& scriptSig,
                       const ftc::script::Script& scriptPubKey,
                       const std::vector<std::vector<uint8_t>>* witness,
                       uint32_t flags,
                       const Transaction& tx,
                       unsigned int input_index,
                       uint64_t amount,
                       ftc::script::ScriptError* error) const;
};

//-----------------------------------------------------------------------------
// Utility Functions
//-----------------------------------------------------------------------------

// Calculate median time past from last 11 blocks
uint32_t getMedianTimePast(uint64_t height,
                            const std::function<uint32_t(uint64_t)>& getBlockTime);

// Check locktime against block height/time
bool checkLocktime(int64_t locktime, uint64_t block_height, uint32_t block_time);

// Check sequence lock
bool checkSequence(uint32_t sequence, uint64_t age_blocks, uint32_t age_seconds);

// Count signature operations in a block
size_t countBlockSigOps(const Block& block);

// Count signature operations in a transaction
size_t countTxSigOps(const Transaction& tx, bool accurate);

// Calculate transaction weight
size_t getTxWeight(const Transaction& tx);

// Calculate block weight
size_t getBlockWeight(const Block& block);

} // namespace chain
} // namespace ftc

#endif // FTC_CHAIN_CONSENSUS_H
