// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "miner/difficulty.h"

// ===========================================================================
// Miner :: bits_to_target / target_to_bits roundtrip
// ===========================================================================

TEST_CASE(Miner, BitsTargetRoundtrip) {
    // Genesis / easiest difficulty bits: 0x1d00ffff.
    uint32_t genesis_bits = 0x1d00ffff;
    core::uint256 target = miner::bits_to_target(genesis_bits);

    // The target should be non-zero.
    CHECK(!target.is_zero());

    // Converting back to bits should yield the original compact value.
    uint32_t roundtripped = miner::target_to_bits(target);
    CHECK_EQ(roundtripped, genesis_bits);

    // A second known value: higher difficulty (smaller target).
    uint32_t harder_bits = 0x1b0404cb;
    core::uint256 harder_target = miner::bits_to_target(harder_bits);
    CHECK(!harder_target.is_zero());

    uint32_t harder_roundtripped = miner::target_to_bits(harder_target);
    CHECK_EQ(harder_roundtripped, harder_bits);

    // The harder target should be numerically less than the genesis target.
    CHECK(harder_target < target);
}

// ===========================================================================
// Miner :: get_difficulty
// ===========================================================================

TEST_CASE(Miner, GetDifficulty) {
    // Genesis bits 0x1d00ffff should correspond to difficulty 1.0.
    double diff_genesis = miner::get_difficulty(0x1d00ffff);
    CHECK_NEAR(diff_genesis, 1.0, 0.0001);

    // A smaller target (harder bits) should yield a higher difficulty.
    double diff_harder = miner::get_difficulty(0x1b0404cb);
    CHECK(diff_harder > 1.0);

    // Harder difficulty must be strictly greater than genesis difficulty.
    CHECK(diff_harder > diff_genesis);
}

// ===========================================================================
// Miner :: estimate_hashrate
// ===========================================================================

TEST_CASE(Miner, EstimateHashrate) {
    // hashrate = difficulty * 2^32 / block_time
    // For difficulty 1.0 and 600-second block time:
    double hr = miner::estimate_hashrate(1.0, 600.0);
    CHECK(hr > 0.0);

    // Expected: 2^32 / 600 ~ 7.158 million hashes/sec.
    double expected = 4294967296.0 / 600.0;
    CHECK_NEAR(hr, expected, expected * 0.001);

    // Higher difficulty should give proportionally higher hashrate.
    double hr_10x = miner::estimate_hashrate(10.0, 600.0);
    CHECK_NEAR(hr_10x, hr * 10.0, hr * 0.01);
}

// ===========================================================================
// Miner :: get_block_proof
// ===========================================================================

TEST_CASE(Miner, GetBlockProof) {
    // Genesis bits should yield non-zero proof-of-work value.
    core::uint256 proof = miner::get_block_proof(0x1d00ffff);
    CHECK(!proof.is_zero());

    // Harder bits should yield more proof (more expected hashes).
    core::uint256 proof_harder = miner::get_block_proof(0x1b0404cb);
    CHECK(!proof_harder.is_zero());
    CHECK(proof_harder > proof);

    // Zero bits (target = 0) should yield a zero or well-defined result.
    // Work = 2^256 / (target+1); with bits=0, target is zero,
    // so work = 2^256 / 1 which is huge, but the implementation may
    // return zero as a sentinel for an invalid input.
    core::uint256 proof_zero = miner::get_block_proof(0);
    // We just verify it does not crash. The value itself is
    // implementation-defined for invalid input.
    (void)proof_zero;
    CHECK(true);
}
