#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// BlockAssembler -- transaction selection for block template construction
//
// Selects transactions from the mempool for inclusion in a new block,
// optimizing total fee revenue while respecting consensus limits on
// block weight and signature operations.
//
// Algorithm: greedy by ancestor fee rate (fee/vbyte), which is optimal
// for maximizing miner revenue when there are no hard package dependencies.
// ---------------------------------------------------------------------------

#include "core/error.h"
#include "mempool/entry.h"
#include "mempool/mempool.h"
#include "primitives/amount.h"
#include "primitives/transaction.h"

#include <cstdint>
#include <vector>

namespace miner {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum block weight in weight units (4 MWU, matching consensus).
static constexpr int64_t MAX_BLOCK_WEIGHT = 4'000'000;

/// Maximum signature operations per block.
static constexpr int MAX_BLOCK_SIGOPS = 80'000;

/// Default maximum block weight for template assembly.
/// Slightly below the consensus max to leave room for the coinbase.
static constexpr int64_t DEFAULT_BLOCK_MAX_WEIGHT = 3'996'000;

/// Default maximum sigops for template assembly.
static constexpr int DEFAULT_BLOCK_MAX_SIGOPS = 79'000;

/// Weight of the coinbase transaction (approximate reservation).
static constexpr int64_t COINBASE_WEIGHT_RESERVE = 4000;

/// Maximum number of transactions to consider from the mempool.
/// This is a practical limit to bound assembly time.
static constexpr size_t MAX_TX_CANDIDATES = 100'000;

// ---------------------------------------------------------------------------
// TxPackage -- a transaction and its mining-relevant metadata
// ---------------------------------------------------------------------------

/// Represents a candidate transaction for block inclusion along with
/// its fee, weight, and sigop cost.
struct TxPackage {
    /// The transaction.
    primitives::Transaction tx;

    /// The transaction ID.
    core::uint256 txid;

    /// Fee paid by this transaction.
    primitives::Amount fee;

    /// Weight of this transaction in weight units.
    int64_t weight = 0;

    /// Estimated signature operation count.
    int sigop_count = 0;

    /// Virtual size in vbytes.
    size_t vsize = 0;

    /// Fee rate in sat/vB.
    [[nodiscard]] double fee_rate() const {
        return vsize > 0
            ? static_cast<double>(fee.value()) / static_cast<double>(vsize)
            : 0.0;
    }

    /// Ancestor fee rate (from mempool entry, used for sorting).
    double ancestor_fee_rate = 0.0;

    /// Number of in-mempool ancestors.
    size_t ancestor_count = 1;

    /// Total ancestor weight (sum of vsizes of ancestors).
    size_t ancestor_size = 0;
};

// ---------------------------------------------------------------------------
// AssemblyResult -- the output of block assembly
// ---------------------------------------------------------------------------

/// The result of assembling transactions for a block.
struct AssemblyResult {
    /// The selected transactions, in block order (topologically sorted).
    std::vector<primitives::Transaction> transactions;

    /// Total fees collected from the selected transactions.
    primitives::Amount total_fees;

    /// Total weight of the selected transactions.
    int64_t total_weight = 0;

    /// Total signature operations.
    int total_sigops = 0;

    /// Number of transactions selected.
    size_t tx_count = 0;

    /// Number of transactions skipped (due to conflicts, limits, etc.).
    size_t skipped_count = 0;
};

// ---------------------------------------------------------------------------
// BlockAssembler
// ---------------------------------------------------------------------------

/// Selects transactions from the mempool to maximize block fee revenue
/// while respecting consensus weight and sigop limits.
class BlockAssembler {
public:
    /// Construct a block assembler with default limits.
    BlockAssembler();

    /// Construct a block assembler with custom limits.
    ///
    /// @param max_weight  Maximum block weight in weight units.
    /// @param max_sigops  Maximum signature operations per block.
    BlockAssembler(int64_t max_weight, int max_sigops);

    // -- Assembly -----------------------------------------------------------

    /// Assemble a set of transactions from the mempool.
    ///
    /// Algorithm:
    ///   1. Fetch all mempool entries sorted by ancestor fee rate (descending).
    ///   2. For each entry, check:
    ///      a. Does adding it (and its ancestors) exceed the weight limit?
    ///      b. Does adding it exceed the sigop limit?
    ///      c. Does it conflict with any already-selected transaction?
    ///      d. Does it violate ancestor/descendant package limits?
    ///   3. If all checks pass, add the transaction (and ancestors).
    ///   4. Continue until the mempool is exhausted or limits are reached.
    ///
    /// The returned transactions are in topological order (parents before
    /// children), suitable for direct inclusion in a block after the
    /// coinbase transaction.
    ///
    /// @param mempool     The transaction mempool to select from.
    /// @param max_weight  Override max weight (0 = use default).
    /// @param max_sigops  Override max sigops (0 = use default).
    /// @returns           The assembly result with selected transactions.
    [[nodiscard]] AssemblyResult assemble(
        const mempool::Mempool& mempool,
        int64_t max_weight = 0,
        int max_sigops = 0) const;

    // -- Configuration -----------------------------------------------------

    /// Set the maximum block weight.
    void set_max_weight(int64_t weight) { max_weight_ = weight; }

    /// Set the maximum sigops per block.
    void set_max_sigops(int sigops) { max_sigops_ = sigops; }

    /// Set the minimum fee rate (sat/vB) for transaction inclusion.
    void set_min_fee_rate(double rate) { min_fee_rate_ = rate; }

    /// Get the maximum block weight.
    [[nodiscard]] int64_t max_weight() const { return max_weight_; }

    /// Get the maximum sigops per block.
    [[nodiscard]] int max_sigops() const { return max_sigops_; }

private:
    int64_t max_weight_ = DEFAULT_BLOCK_MAX_WEIGHT;
    int max_sigops_ = DEFAULT_BLOCK_MAX_SIGOPS;
    double min_fee_rate_ = 0.0;

    /// Estimate the sigop count for a transaction.
    /// Uses a simple heuristic based on script types.
    [[nodiscard]] static int estimate_sigops(
        const primitives::Transaction& tx);
};

} // namespace miner
