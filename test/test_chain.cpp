// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "chain/block_index.h"
#include "chain/chain.h"
#include "chain/coins.h"
#include "chain/utxo/cache.h"

#include <cstdint>
#include <vector>

// ============================================================================
// BlockIndex tests
// ============================================================================

TEST_CASE(BlockIndex, default_construction) {
    chain::BlockIndex idx;

    // A default-constructed BlockIndex should have sensible defaults.
    CHECK_EQ(idx.height, -1);
    CHECK_EQ(idx.version, 0);
    CHECK_EQ(idx.time, static_cast<uint32_t>(0));
    CHECK_EQ(idx.bits, static_cast<uint32_t>(0));
    CHECK_EQ(idx.nonce, static_cast<uint32_t>(0));
    CHECK_EQ(idx.tx_count, 0);
    CHECK_EQ(idx.chain_tx, static_cast<int64_t>(0));
    CHECK_EQ(idx.status, static_cast<uint32_t>(chain::BlockIndex::BLOCK_VALID_UNKNOWN));
    CHECK(idx.prev == nullptr);
    CHECK(idx.block_hash.is_zero());
    CHECK(idx.hash_merkle_root.is_zero());
    CHECK(idx.chain_work.is_zero());
    CHECK(!idx.has_data());
    CHECK(!idx.has_undo());
    CHECK(!idx.is_failed());
}

TEST_CASE(BlockIndex, set_properties_and_status) {
    chain::BlockIndex genesis;
    genesis.height = 0;
    genesis.time = 1700000000;
    genesis.block_hash = core::uint256::from_hex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    genesis.version = 1;
    genesis.tx_count = 1;

    CHECK_EQ(genesis.height, 0);
    CHECK_EQ(genesis.time, static_cast<uint32_t>(1700000000));
    CHECK_EQ(genesis.version, 1);
    CHECK_EQ(genesis.tx_count, 1);
    CHECK(!genesis.block_hash.is_zero());

    // Build a second block linked to genesis.
    chain::BlockIndex block1;
    block1.height = 1;
    block1.prev = &genesis;
    block1.time = 1700000600;

    CHECK_EQ(block1.height, 1);
    CHECK(block1.prev == &genesis);
    CHECK_EQ(block1.prev->height, 0);

    // Status flags: mark as having data.
    block1.status = chain::BlockIndex::BLOCK_HAVE_DATA;
    CHECK(block1.has_data());
    CHECK(!block1.has_undo());
    CHECK(!block1.is_failed());

    // Mark as failed.
    chain::BlockIndex bad_block;
    bad_block.status = chain::BlockIndex::BLOCK_FAILED_VALID;
    CHECK(bad_block.is_failed());
}

TEST_CASE(BlockIndex, get_ancestor) {
    // Build a small chain: genesis -> b1 -> b2 -> b3
    chain::BlockIndex genesis;
    genesis.height = 0;

    chain::BlockIndex b1;
    b1.height = 1;
    b1.prev = &genesis;

    chain::BlockIndex b2;
    b2.height = 2;
    b2.prev = &b1;

    chain::BlockIndex b3;
    b3.height = 3;
    b3.prev = &b2;

    // Walk back to each ancestor.
    CHECK(b3.get_ancestor(3) == &b3);
    CHECK(b3.get_ancestor(2) == &b2);
    CHECK(b3.get_ancestor(1) == &b1);
    CHECK(b3.get_ancestor(0) == &genesis);

    // Out-of-range returns nullptr.
    CHECK(b3.get_ancestor(4) == nullptr);
    CHECK(b3.get_ancestor(-1) == nullptr);
}

// ============================================================================
// Coin tests
// ============================================================================

TEST_CASE(Coin, construction_and_is_spent) {
    // Default-constructed coin: zero amount, not coinbase, not spent.
    chain::Coin default_coin;
    CHECK_EQ(default_coin.height, 0);
    CHECK_EQ(default_coin.is_coinbase, false);
    // Default TxOutput has amount 0 -- that is NOT the "spent" sentinel.
    CHECK(!default_coin.is_spent());

    // Construct a coin with explicit values.
    primitives::TxOutput txo(primitives::Amount(50000), {0x76, 0xa9, 0x14});
    chain::Coin coin(txo, 100, true);

    CHECK_EQ(coin.height, 100);
    CHECK_EQ(coin.is_coinbase, true);
    CHECK_EQ(coin.out.amount, primitives::Amount(50000));
    CHECK(!coin.is_spent());

    // A coin with the sentinel amount (-1) is considered spent.
    primitives::TxOutput spent_out(primitives::Amount(-1), {});
    chain::Coin spent_coin(spent_out, 200, false);
    CHECK(spent_coin.is_spent());
}

TEST_CASE(Coin, serialize_deserialize_roundtrip) {
    // Create a coin with a known script and amount.
    std::vector<uint8_t> script = {0x76, 0xa9, 0x14, 0xab, 0xcd, 0xef,
                                   0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                   0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                   0x0d, 0x0e, 0x0f, 0x88, 0xac};
    primitives::TxOutput txo(primitives::Amount(123456789), script);
    chain::Coin original(txo, 500000, true);

    // Serialize to bytes.
    std::vector<uint8_t> data = original.serialize();
    CHECK(!data.empty());

    // Deserialize back.
    auto result = chain::Coin::deserialize(std::span<const uint8_t>(data));
    CHECK_OK(result);

    const chain::Coin& restored = result.value();
    CHECK_EQ(restored.height, original.height);
    CHECK_EQ(restored.is_coinbase, original.is_coinbase);
    CHECK_EQ(restored.out.amount, original.out.amount);
    CHECK_EQ(restored.out.script_pubkey.size(), original.out.script_pubkey.size());
    CHECK(restored.out.script_pubkey == original.out.script_pubkey);
    CHECK(!restored.is_spent());
}

TEST_CASE(Coin, deserialize_bad_data) {
    // Attempting to deserialize an empty span should produce an error.
    std::vector<uint8_t> empty_data;
    auto result = chain::Coin::deserialize(std::span<const uint8_t>(empty_data));
    CHECK_ERR(result);

    // Truncated data (just a few bytes) should also fail.
    std::vector<uint8_t> short_data = {0x01, 0x02, 0x03};
    auto result2 = chain::Coin::deserialize(std::span<const uint8_t>(short_data));
    CHECK_ERR(result2);
}

// ============================================================================
// Chain tests
// ============================================================================

TEST_CASE(Chain, empty_chain) {
    chain::Chain c;

    CHECK(c.tip() == nullptr);
    CHECK(c.genesis() == nullptr);
    CHECK_EQ(c.height(), -1);
    CHECK(c.at(0) == nullptr);
    CHECK(c[0] == nullptr);
    CHECK(!c.contains(nullptr));
}

TEST_CASE(Chain, set_tip_and_access) {
    // Build a 3-block chain in memory.
    chain::BlockIndex genesis;
    genesis.height = 0;
    genesis.block_hash = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001");

    chain::BlockIndex b1;
    b1.height = 1;
    b1.prev = &genesis;
    b1.block_hash = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000002");

    chain::BlockIndex b2;
    b2.height = 2;
    b2.prev = &b1;
    b2.block_hash = core::uint256::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000003");

    chain::Chain c;
    c.set_tip(&b2);

    // Tip, genesis, and height.
    CHECK(c.tip() == &b2);
    CHECK(c.genesis() == &genesis);
    CHECK_EQ(c.height(), 2);

    // Access by height.
    CHECK(c.at(0) == &genesis);
    CHECK(c.at(1) == &b1);
    CHECK(c.at(2) == &b2);
    CHECK(c.at(3) == nullptr);
    CHECK(c.at(-1) == nullptr);

    // Containment.
    CHECK(c.contains(&genesis));
    CHECK(c.contains(&b1));
    CHECK(c.contains(&b2));

    // A block not in the chain should not be contained.
    chain::BlockIndex orphan;
    orphan.height = 1;
    CHECK(!c.contains(&orphan));

    // Reset to empty.
    c.set_tip(nullptr);
    CHECK(c.tip() == nullptr);
    CHECK_EQ(c.height(), -1);
}
