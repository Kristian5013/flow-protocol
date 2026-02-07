// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "mempool/entry.h"
#include "mempool/mempool.h"
#include "mempool/policy.h"

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Helper: build a minimal valid transaction for testing
// ============================================================================

namespace {

/// Create a simple 1-input, 1-output transaction with the given version.
/// The input references a made-up previous txid. The output has the given
/// amount and a dummy P2PKH-like scriptPubKey (25 bytes).
primitives::Transaction make_simple_tx(int64_t output_amount,
                                       int32_t version = 2) {
    // Dummy previous outpoint.
    core::uint256 prev_txid = core::uint256::from_hex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    primitives::TxInput input(primitives::OutPoint(prev_txid, 0), {}, 0xFFFFFFFD);

    // Dummy P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    std::vector<uint8_t> script(25, 0x00);
    script[0] = 0x76; // OP_DUP
    script[1] = 0xa9; // OP_HASH160
    script[2] = 0x14; // push 20 bytes
    // bytes 3..22 are the hash (left as zeros)
    script[23] = 0x88; // OP_EQUALVERIFY
    script[24] = 0xac; // OP_CHECKSIG

    primitives::TxOutput output(primitives::Amount(output_amount), script);

    return primitives::Transaction(
        std::vector<primitives::TxInput>{input},
        std::vector<primitives::TxOutput>{output},
        version,
        0 /* locktime */);
}

} // anonymous namespace

// ============================================================================
// MempoolEntry tests
// ============================================================================

TEST_CASE(MempoolEntry, from_tx_basic_fields) {
    auto tx = make_simple_tx(50000);
    primitives::Amount fee(1000);
    int32_t height = 800000;
    int64_t time = 1700000000;

    mempool::MempoolEntry entry =
        mempool::MempoolEntry::from_tx(tx, fee, height, time);

    // Core fields.
    CHECK_EQ(entry.fee, primitives::Amount(1000));
    CHECK_EQ(entry.height, height);
    CHECK_EQ(entry.time, time);

    // The txid should match the transaction's txid.
    CHECK(entry.txid == tx.txid());

    // Size/vsize should be positive for a non-empty transaction.
    CHECK(entry.size > 0);
    CHECK(entry.vsize > 0);

    // Accessor methods on the entry should reflect the underlying transaction.
    CHECK_EQ(entry.input_count(), tx.vin().size());
    CHECK_EQ(entry.output_count(), tx.vout().size());

    // Ancestor/descendant fields start at self-only values.
    CHECK_EQ(entry.ancestor_count, static_cast<size_t>(1));
    CHECK_EQ(entry.descendant_count, static_cast<size_t>(1));
}

TEST_CASE(MempoolEntry, fee_rate_computation) {
    auto tx = make_simple_tx(50000);
    primitives::Amount fee(2000);
    mempool::MempoolEntry entry =
        mempool::MempoolEntry::from_tx(tx, fee, 100, 1700000000);

    // fee_rate() is fee / vsize in sat/vB.
    double expected_rate = 2000.0 / static_cast<double>(entry.vsize);
    CHECK_NEAR(entry.fee_rate(), expected_rate, 0.01);

    // fee_rate_per_kvb() should be approximately fee_rate * 1000.
    CHECK_NEAR(static_cast<double>(entry.fee_rate_per_kvb()),
               entry.fee_rate() * 1000.0, 1.0);

    // With self-only ancestor/descendant stats, all three rates should match.
    CHECK_NEAR(entry.ancestor_fee_rate(), entry.fee_rate(), 0.01);
    CHECK_NEAR(entry.descendant_fee_rate(), entry.fee_rate(), 0.01);
}

TEST_CASE(MempoolEntry, scoring_and_comparison) {
    // Create two entries with different fees but same tx structure.
    auto tx1 = make_simple_tx(50000);
    auto tx2 = make_simple_tx(49000);

    // Higher fee -> higher fee rate (same vsize).
    mempool::MempoolEntry high_fee =
        mempool::MempoolEntry::from_tx(tx1, primitives::Amount(5000), 100, 1700000000);
    mempool::MempoolEntry low_fee =
        mempool::MempoolEntry::from_tx(tx2, primitives::Amount(500), 100, 1700000000);

    CHECK(high_fee.fee_rate() > low_fee.fee_rate());
    CHECK(high_fee.mining_score() > low_fee.mining_score());
    CHECK(high_fee.eviction_score() > low_fee.eviction_score());

    // is_better_for_mining: higher score wins.
    CHECK(high_fee.is_better_for_mining(low_fee));
    CHECK(!low_fee.is_better_for_mining(high_fee));

    // should_evict_before: lower score loses (gets evicted first).
    CHECK(low_fee.should_evict_before(high_fee));
    CHECK(!high_fee.should_evict_before(low_fee));
}

// ============================================================================
// Policy tests
// ============================================================================

TEST_CASE(Policy, constants_sanity) {
    // Verify important policy constants have expected values.
    CHECK_EQ(mempool::MIN_RELAY_FEE, static_cast<int64_t>(1000));
    CHECK_EQ(mempool::DUST_THRESHOLD, static_cast<int64_t>(546));
    CHECK_EQ(mempool::MAX_STANDARD_TX_WEIGHT, static_cast<size_t>(400000));
    CHECK_EQ(mempool::MAX_STANDARD_TX_SIZE, static_cast<size_t>(100000));
    CHECK_EQ(mempool::MAX_ANCESTORS, static_cast<size_t>(25));
    CHECK_EQ(mempool::MAX_DESCENDANTS, static_cast<size_t>(25));
}

TEST_CASE(Policy, check_standard_valid_tx) {
    // A simple 1-in/1-out version-2 transaction with a reasonable output
    // should pass standardness checks.
    auto tx = make_simple_tx(100000);
    auto result = mempool::check_standard(tx);
    CHECK_OK(result);
}

TEST_CASE(Policy, check_standard_bad_version) {
    // Version 0 is non-standard. check_standard should reject it.
    auto tx = make_simple_tx(100000, /*version=*/0);
    auto result = mempool::check_standard(tx);
    CHECK_ERR(result);
}

TEST_CASE(Policy, check_min_relay_fee) {
    auto tx = make_simple_tx(100000);

    // A generous fee should pass.
    auto result_ok = mempool::check_min_relay_fee(tx, primitives::Amount(10000));
    CHECK_OK(result_ok);

    // A zero fee should fail (the tx has nonzero vsize so needs > 0 fee).
    auto result_fail = mempool::check_min_relay_fee(tx, primitives::Amount(0));
    CHECK_ERR(result_fail);
}

TEST_CASE(Policy, run_all_policy_checks) {
    auto tx = make_simple_tx(100000);
    primitives::Amount fee(10000);

    mempool::PolicyCheckResult pcr = mempool::run_all_policy_checks(tx, fee);

    // With a well-formed tx and sufficient fee, all checks should pass.
    CHECK(pcr.is_standard);
    CHECK(pcr.fee_ok);
    CHECK(pcr.dust_ok);
    CHECK(pcr.all_passed());
    CHECK(pcr.fee_rate > 0.0);
}

// ============================================================================
// Mempool tests
// ============================================================================

TEST_CASE(Mempool, empty_pool) {
    mempool::Mempool pool;

    CHECK_EQ(pool.size(), static_cast<size_t>(0));
    CHECK_EQ(pool.total_tx_size(), static_cast<size_t>(0));

    // Looking up a non-existent txid should return nullptr / false.
    core::uint256 fake_txid;
    CHECK(!pool.exists(fake_txid));
    CHECK(pool.get(fake_txid) == nullptr);

    // get_all_txids should be empty.
    auto all = pool.get_all_txids();
    CHECK(all.empty());
}

TEST_CASE(Mempool, add_unchecked_and_lookup) {
    mempool::Mempool pool;

    auto tx = make_simple_tx(100000);
    primitives::Amount fee(5000);
    mempool::MempoolEntry entry =
        mempool::MempoolEntry::from_tx(tx, fee, 800000, 1700000000);

    core::uint256 txid = entry.txid;

    // add_unchecked bypasses policy checks.
    auto result = pool.add_unchecked(std::move(entry));
    CHECK_OK(result);

    // Pool should now contain exactly one transaction.
    CHECK_EQ(pool.size(), static_cast<size_t>(1));
    CHECK(pool.exists(txid));

    const mempool::MempoolEntry* found = pool.get(txid);
    CHECK(found != nullptr);
    if (found) {
        CHECK(found->txid == txid);
        CHECK_EQ(found->fee, primitives::Amount(5000));
    }

    // get_all_txids should return the one txid.
    auto all = pool.get_all_txids();
    CHECK_EQ(all.size(), static_cast<size_t>(1));
}

TEST_CASE(Mempool, remove_transaction) {
    mempool::Mempool pool;

    auto tx = make_simple_tx(100000);
    primitives::Amount fee(5000);
    mempool::MempoolEntry entry =
        mempool::MempoolEntry::from_tx(tx, fee, 800000, 1700000000);
    core::uint256 txid = entry.txid;

    auto result = pool.add_unchecked(std::move(entry));
    CHECK_OK(result);
    CHECK_EQ(pool.size(), static_cast<size_t>(1));

    // Remove the transaction.
    pool.remove(txid);

    CHECK_EQ(pool.size(), static_cast<size_t>(0));
    CHECK(!pool.exists(txid));
    CHECK(pool.get(txid) == nullptr);
}

TEST_CASE(Mempool, clear_pool) {
    mempool::Mempool pool;

    // Add two different transactions.
    auto tx1 = make_simple_tx(100000);
    auto tx2 = make_simple_tx(200000);

    mempool::MempoolEntry e1 =
        mempool::MempoolEntry::from_tx(tx1, primitives::Amount(1000), 800000, 1700000000);
    mempool::MempoolEntry e2 =
        mempool::MempoolEntry::from_tx(tx2, primitives::Amount(2000), 800000, 1700000001);

    CHECK_OK(pool.add_unchecked(std::move(e1)));
    CHECK_OK(pool.add_unchecked(std::move(e2)));
    CHECK_EQ(pool.size(), static_cast<size_t>(2));

    pool.clear();
    CHECK_EQ(pool.size(), static_cast<size_t>(0));
    CHECK(pool.get_all_txids().empty());
}
