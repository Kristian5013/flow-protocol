// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license.

#include "test_framework.h"

#include "consensus/params.h"
#include "consensus/amount.h"
#include "consensus/subsidy.h"
#include "consensus/time.h"
#include "consensus/merkle.h"

#include "primitives/amount.h"
#include "primitives/block.h"
#include "primitives/transaction.h"

// ===========================================================================
// ConsensusParams
// ===========================================================================

TEST_CASE(ConsensusParams, default_construction) {
    consensus::ConsensusParams params;

    // Check important defaults.
    CHECK_EQ(params.pow_target_spacing, int64_t{600});
    CHECK_EQ(params.pow_target_timespan, int64_t{2016 * 600});
    CHECK_EQ(params.subsidy_halving_interval, 210'000);
    CHECK_EQ(params.coinbase_maturity, 100);
    CHECK_EQ(params.max_block_weight, uint32_t{4'000'000});
    CHECK_EQ(params.witness_scale_factor, 4);
    CHECK_EQ(params.segwit_height, 0);

    // Difficulty adjustment interval derived from spacing and timespan.
    CHECK_EQ(params.difficulty_adjustment_interval(), int64_t{2016});
}

TEST_CASE(ConsensusParams, mainnet_params) {
    const auto& mainnet = consensus::ConsensusParams::mainnet_params();

    // Mainnet should have standard Bitcoin-like values.
    CHECK_EQ(mainnet.pow_target_spacing, int64_t{600});
    CHECK_EQ(mainnet.subsidy_halving_interval, 210'000);
    CHECK_EQ(mainnet.default_port, uint16_t{9333});
    CHECK_EQ(mainnet.rpc_port, uint16_t{9332});
    CHECK_EQ(mainnet.max_block_weight, uint32_t{4'000'000});

    // BIP34/65/66 and segwit are genesis-active (height 0).
    CHECK_EQ(mainnet.bip34_height, 0);
    CHECK_EQ(mainnet.bip65_height, 0);
    CHECK_EQ(mainnet.bip66_height, 0);
    CHECK_EQ(mainnet.segwit_height, 0);

}

// ===========================================================================
// Consensus Amount
// ===========================================================================

TEST_CASE(ConsensusAmount, constants_and_check_money_range) {
    // Re-exported constants match primitives.
    CHECK_EQ(consensus::COIN, primitives::Amount::COIN);
    CHECK_EQ(consensus::MAX_MONEY, primitives::Amount::MAX_MONEY);

    // check_money_range: valid values.
    CHECK(consensus::check_money_range(primitives::Amount(int64_t{0})));
    CHECK(consensus::check_money_range(
        primitives::Amount(primitives::Amount::MAX_MONEY)));

    // check_money_range: invalid values.
    CHECK(!consensus::check_money_range(primitives::Amount(int64_t{-1})));
    CHECK(!consensus::check_money_range(
        primitives::Amount(primitives::Amount::MAX_MONEY + 1)));
}

// ===========================================================================
// Subsidy
// ===========================================================================

TEST_CASE(Subsidy, genesis_block_reward) {
    const auto& params = consensus::ConsensusParams::mainnet_params();

    // Block 0 (genesis): 50 FTC.
    primitives::Amount subsidy0 = consensus::get_block_subsidy(0, params);
    CHECK_EQ(subsidy0.value(), int64_t{50} * primitives::Amount::COIN);

    // Block 1 should also be 50 FTC (same first era).
    primitives::Amount subsidy1 = consensus::get_block_subsidy(1, params);
    CHECK_EQ(subsidy1.value(), int64_t{50} * primitives::Amount::COIN);
}

TEST_CASE(Subsidy, halving_schedule) {
    const auto& params = consensus::ConsensusParams::mainnet_params();
    const int interval = params.subsidy_halving_interval;  // 210,000

    // Just before first halving: still 50 FTC.
    primitives::Amount before_halving =
        consensus::get_block_subsidy(interval - 1, params);
    CHECK_EQ(before_halving.value(), int64_t{50} * primitives::Amount::COIN);

    // First halving (block 210,000): 25 FTC.
    primitives::Amount at_halving =
        consensus::get_block_subsidy(interval, params);
    CHECK_EQ(at_halving.value(), int64_t{25} * primitives::Amount::COIN);

    // Second halving (block 420,000): 12.5 FTC.
    primitives::Amount second =
        consensus::get_block_subsidy(2 * interval, params);
    CHECK_EQ(second.value(), int64_t{12'5000'0000});

    // After 64 halvings the subsidy should be zero.
    primitives::Amount far_future =
        consensus::get_block_subsidy(64 * interval, params);
    CHECK_EQ(far_future.value(), int64_t{0});
}

TEST_CASE(Subsidy, block_reward_includes_fees) {
    const auto& params = consensus::ConsensusParams::mainnet_params();

    primitives::Amount fees(int64_t{10'000});
    primitives::Amount reward = consensus::get_block_reward(0, fees, params);

    // Reward = subsidy (50 FTC) + fees.
    int64_t expected = int64_t{50} * primitives::Amount::COIN + int64_t{10'000};
    CHECK_EQ(reward.value(), expected);
}

// ===========================================================================
// Time
// ===========================================================================

TEST_CASE(Time, median_time_past) {
    // Empty timestamps -> MTP is 0.
    CHECK_EQ(consensus::get_median_time_past({}), int64_t{0});

    // Single timestamp -> MTP is that timestamp.
    CHECK_EQ(consensus::get_median_time_past({1000}), int64_t{1000});

    // Odd number of timestamps: median is the middle element.
    // Input is most-recent-first: {5, 4, 3, 2, 1}.
    // Sorted: {1, 2, 3, 4, 5} -> median is 3.
    CHECK_EQ(
        consensus::get_median_time_past({5, 4, 3, 2, 1}),
        int64_t{3});

    // Full 11-element span.
    std::vector<int64_t> timestamps = {
        1100, 1000, 900, 800, 700, 600, 500, 400, 300, 200, 100
    };
    int64_t mtp = consensus::get_median_time_past(timestamps);
    // Sorted: 100..1100, median (index 5 of 11) = 600.
    CHECK_EQ(mtp, int64_t{600});
}

TEST_CASE(Time, check_block_time_rules) {
    // Constants.
    CHECK_EQ(consensus::MEDIAN_TIME_SPAN, 11);
    CHECK_EQ(consensus::MAX_FUTURE_BLOCK_TIME, int64_t{7200});

    int64_t mtp = 1000;
    int64_t adjusted_time = 2000;

    // Valid: block_time > mtp AND block_time <= adjusted_time + 7200.
    CHECK(consensus::check_block_time(1001, mtp, adjusted_time));
    CHECK(consensus::check_block_time(2000 + 7200, mtp, adjusted_time));

    // Invalid: block_time == mtp (must be strictly greater).
    CHECK(!consensus::check_block_time(1000, mtp, adjusted_time));

    // Invalid: block_time < mtp.
    CHECK(!consensus::check_block_time(999, mtp, adjusted_time));

    // Invalid: block_time too far in the future.
    CHECK(!consensus::check_block_time(2000 + 7201, mtp, adjusted_time));
}

// ===========================================================================
// Merkle
// ===========================================================================

TEST_CASE(Merkle, empty_leaves) {
    // Merkle root of an empty vector is a zero hash.
    std::vector<core::uint256> empty;
    core::uint256 root = consensus::compute_merkle_root(empty);
    CHECK(root.is_zero());
}

TEST_CASE(Merkle, single_leaf) {
    // Merkle root of a single leaf equals that leaf's hash
    // (since there is nothing to pair with, the sole hash IS the root).
    core::uint256 leaf = core::uint256::from_hex(
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    std::vector<core::uint256> leaves = {leaf};
    core::uint256 root = consensus::compute_merkle_root(leaves);
    CHECK(root == leaf);
}

