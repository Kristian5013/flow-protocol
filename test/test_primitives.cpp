// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license.

#include "test_framework.h"

#include "primitives/amount.h"
#include "primitives/outpoint.h"
#include "primitives/txin.h"
#include "primitives/txout.h"
#include "primitives/transaction.h"
#include "primitives/block_header.h"
#include "primitives/fees.h"
#include "primitives/address.h"

// ===========================================================================
// Amount
// ===========================================================================

TEST_CASE(Amount, construction_and_constants) {
    // Default construction yields zero.
    primitives::Amount zero;
    CHECK_EQ(zero.value(), int64_t{0});

    // Explicit construction.
    primitives::Amount one_coin(primitives::Amount::COIN);
    CHECK_EQ(one_coin.value(), int64_t{100'000'000});

    // COIN constant.
    CHECK_EQ(primitives::Amount::COIN, int64_t{100'000'000});

    // MAX_MONEY constant: 21 million coins.
    CHECK_EQ(primitives::Amount::MAX_MONEY, int64_t{21'000'000} * int64_t{100'000'000});

    // ZERO_AMOUNT convenience constant.
    CHECK_EQ(primitives::ZERO_AMOUNT.value(), int64_t{0});
}

TEST_CASE(Amount, from_value_valid_and_invalid) {
    // Valid: zero.
    auto r0 = primitives::Amount::from_value(0);
    CHECK_OK(r0);
    CHECK_EQ(r0.value().value(), int64_t{0});

    // Valid: MAX_MONEY.
    auto rmax = primitives::Amount::from_value(primitives::Amount::MAX_MONEY);
    CHECK_OK(rmax);
    CHECK_EQ(rmax.value().value(), primitives::Amount::MAX_MONEY);

    // Invalid: negative value.
    auto rneg = primitives::Amount::from_value(-1);
    CHECK_ERR(rneg);

    // Invalid: exceeds MAX_MONEY.
    auto rover = primitives::Amount::from_value(primitives::Amount::MAX_MONEY + 1);
    CHECK_ERR(rover);
}

TEST_CASE(Amount, from_ftc_and_to_ftc) {
    // 1.0 FTC == COIN base units.
    auto r1 = primitives::Amount::from_ftc(1.0);
    CHECK_OK(r1);
    CHECK_EQ(r1.value().value(), primitives::Amount::COIN);

    // Round-trip through to_ftc.
    CHECK_NEAR(r1.value().to_ftc(), 1.0, 1e-8);

    // 0.5 FTC.
    auto r_half = primitives::Amount::from_ftc(0.5);
    CHECK_OK(r_half);
    CHECK_EQ(r_half.value().value(), int64_t{50'000'000});

    // Invalid: negative.
    auto rneg = primitives::Amount::from_ftc(-1.0);
    CHECK_ERR(rneg);
}

TEST_CASE(Amount, arithmetic_and_comparison) {
    primitives::Amount a(int64_t{300});
    primitives::Amount b(int64_t{200});

    // Checked addition.
    auto sum = a + b;
    CHECK_OK(sum);
    CHECK_EQ(sum.value().value(), int64_t{500});

    // Checked subtraction.
    auto diff = a - b;
    CHECK_OK(diff);
    CHECK_EQ(diff.value().value(), int64_t{100});

    // Subtraction yielding negative should error.
    auto neg = b - a;
    CHECK_ERR(neg);

    // is_valid.
    CHECK(a.is_valid());
    primitives::Amount bad(int64_t{-1});
    CHECK(!bad.is_valid());

    // Comparison operators.
    CHECK(a > b);
    CHECK(b < a);
    CHECK(a == primitives::Amount(int64_t{300}));
    CHECK(a != b);

    // In-place operators.
    primitives::Amount c(int64_t{100});
    c += primitives::Amount(int64_t{50});
    CHECK_EQ(c.value(), int64_t{150});
    c -= primitives::Amount(int64_t{30});
    CHECK_EQ(c.value(), int64_t{120});
}

// ===========================================================================
// OutPoint
// ===========================================================================

TEST_CASE(OutPoint, default_and_null) {
    // Default-constructed outpoint is null (zero txid, index 0xFFFFFFFF).
    primitives::OutPoint op;
    CHECK(op.is_null());
    CHECK(op.txid.is_zero());
    CHECK_EQ(op.n, uint32_t{0xFFFFFFFF});
}

TEST_CASE(OutPoint, construction_and_equality) {
    core::uint256 hash = core::uint256::from_hex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    primitives::OutPoint op1(hash, 0);
    CHECK(!op1.is_null());
    CHECK_EQ(op1.n, uint32_t{0});
    CHECK(op1.txid == hash);

    // Equality of identical outpoints.
    primitives::OutPoint op2(hash, 0);
    CHECK(op1 == op2);

    // Different index means not equal.
    primitives::OutPoint op3(hash, 1);
    CHECK(op1 != op3);

    // to_string should not be empty.
    CHECK(!op1.to_string().empty());
}

// ===========================================================================
// TxInput / TxOutput
// ===========================================================================

TEST_CASE(TxInput, construction_and_properties) {
    // Default-constructed input.
    primitives::TxInput input;
    CHECK(input.prevout.is_null());
    CHECK_EQ(input.sequence, primitives::TxInput::SEQUENCE_FINAL);
    CHECK(input.script_sig.empty());
    CHECK(!input.has_witness());

    // Constructed with explicit prevout and script_sig.
    core::uint256 hash = core::uint256::from_hex(
        "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd");
    primitives::OutPoint op(hash, 3);
    std::vector<uint8_t> sig = {0x01, 0x02, 0x03};

    primitives::TxInput in2(op, sig, 0xFFFFFFFE);
    CHECK(!in2.prevout.is_null());
    CHECK_EQ(in2.prevout.n, uint32_t{3});
    CHECK_EQ(in2.sequence, uint32_t{0xFFFFFFFE});
    CHECK_EQ(in2.script_sig.size(), size_t{3});
}

TEST_CASE(TxOutput, construction_and_properties) {
    // Default-constructed output.
    primitives::TxOutput out;
    CHECK(out.script_pubkey.empty());

    // Constructed with amount and script.
    primitives::Amount amt(int64_t{50'000'000});
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    primitives::TxOutput out2(amt, spk);
    CHECK_EQ(out2.amount.value(), int64_t{50'000'000});
    CHECK_EQ(out2.script_pubkey.size(), size_t{3});
    CHECK(!out2.is_null());

    // Null output sentinel.
    primitives::TxOutput null_out(primitives::Amount(int64_t{-1}), {});
    CHECK(null_out.is_null());
}

// ===========================================================================
// Transaction
// ===========================================================================

TEST_CASE(Transaction, empty_transaction) {
    primitives::Transaction tx;
    CHECK(tx.vin().empty());
    CHECK(tx.vout().empty());
    CHECK_EQ(tx.version(), int32_t{2});
    CHECK_EQ(tx.locktime(), uint32_t{0});
    CHECK(!tx.has_witness());
}

TEST_CASE(Transaction, construction_and_txid_determinism) {
    // Build a simple transaction with one input and one output.
    core::uint256 prev_hash = core::uint256::from_hex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    primitives::OutPoint op(prev_hash, 0);
    primitives::TxInput in(op, {0x00}, 0xFFFFFFFF);

    primitives::Amount amt(int64_t{49'000'000});
    primitives::TxOutput out(amt, {0x76, 0xa9});

    primitives::Transaction tx({in}, {out}, 2, 0);

    CHECK_EQ(tx.vin().size(), size_t{1});
    CHECK_EQ(tx.vout().size(), size_t{1});
    CHECK_EQ(tx.version(), int32_t{2});
    CHECK_EQ(tx.locktime(), uint32_t{0});

    // txid must be deterministic: calling it twice yields the same hash.
    const core::uint256& id1 = tx.txid();
    const core::uint256& id2 = tx.txid();
    CHECK(id1 == id2);

    // txid should not be zero for a non-empty transaction.
    CHECK(!tx.txid().is_zero());
}

TEST_CASE(Transaction, coinbase_detection) {
    // A coinbase tx has exactly one input with a null prevout.
    primitives::TxInput cb_in;
    cb_in.prevout = primitives::OutPoint{};  // null (zero hash, 0xFFFFFFFF)
    cb_in.script_sig = {0x04, 0xff, 0xff, 0x00};

    primitives::Amount reward(int64_t{50} * primitives::Amount::COIN);
    primitives::TxOutput cb_out(reward, {0x41});

    primitives::Transaction coinbase_tx({cb_in}, {cb_out}, 2, 0);
    CHECK(coinbase_tx.is_coinbase());

    // Non-coinbase: input with a real prevout.
    core::uint256 real_hash = core::uint256::from_hex(
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    primitives::TxInput normal_in(primitives::OutPoint(real_hash, 0), {}, 0xFFFFFFFF);
    primitives::Transaction normal_tx({normal_in}, {cb_out}, 2, 0);
    CHECK(!normal_tx.is_coinbase());
}

// ===========================================================================
// BlockHeader
// ===========================================================================

TEST_CASE(BlockHeader, default_construction) {
    primitives::BlockHeader hdr;
    CHECK_EQ(hdr.version, int32_t{1});
    CHECK(hdr.prev_hash.is_zero());
    CHECK(hdr.merkle_root.is_zero());
    CHECK_EQ(hdr.timestamp, uint32_t{0});
    CHECK_EQ(hdr.bits, uint32_t{0});
    CHECK_EQ(hdr.nonce, uint32_t{0});
}

TEST_CASE(BlockHeader, properties_and_hash_determinism) {
    primitives::BlockHeader hdr;
    hdr.version = 4;
    hdr.timestamp = 1700000000;
    hdr.bits = 0x1d00ffff;
    hdr.nonce = 42;

    CHECK_EQ(hdr.version, int32_t{4});
    CHECK_EQ(hdr.timestamp, uint32_t{1700000000});
    CHECK_EQ(hdr.bits, uint32_t{0x1d00ffff});
    CHECK_EQ(hdr.nonce, uint32_t{42});

    // Hash is deterministic.
    core::uint256 h1 = hdr.hash();
    core::uint256 h2 = hdr.hash();
    CHECK(h1 == h2);
    CHECK(!h1.is_zero());

    // Serialized size constant.
    CHECK_EQ(primitives::BlockHeader::SERIALIZED_SIZE, size_t{80});

    // serialize_array produces 80 bytes.
    auto arr = hdr.serialize_array();
    CHECK_EQ(arr.size(), size_t{80});
}

// ===========================================================================
// FeeRate
// ===========================================================================

TEST_CASE(FeeRate, construction_and_fee_computation) {
    // Default fee rate is zero.
    primitives::FeeRate zero_rate;
    CHECK_EQ(zero_rate.fee_per_kvb.value(), int64_t{0});

    // 1000 sat/kvB == 1 sat/vB.
    primitives::FeeRate one_sat_per_vb(primitives::Amount(int64_t{1000}));
    CHECK_EQ(one_sat_per_vb.fee_per_kvb.value(), int64_t{1000});

    // Fee for a 250-vB transaction at 1 sat/vB should be 250 (rounded up).
    primitives::Amount fee250 = one_sat_per_vb.compute_fee(250);
    CHECK(fee250.value() >= int64_t{250});

    // Fee for a 1000-vB transaction at 1000 sat/kvB should be exactly 1000.
    primitives::Amount fee1k = one_sat_per_vb.compute_fee(1000);
    CHECK_EQ(fee1k.value(), int64_t{1000});

    // from_fee_and_size round-trip.
    primitives::FeeRate derived =
        primitives::FeeRate::from_fee_and_size(primitives::Amount(int64_t{1000}), 1000);
    CHECK_EQ(derived.fee_per_kvb.value(), int64_t{1000});
}

TEST_CASE(FeeRate, comparison_and_defaults) {
    // Comparison operators.
    primitives::FeeRate low(primitives::Amount(int64_t{500}));
    primitives::FeeRate high(primitives::Amount(int64_t{2000}));
    CHECK(low < high);
    CHECK(high > low);
    CHECK(low != high);

    // Default constants exist and are ordered.
    CHECK(primitives::DEFAULT_MIN_RELAY_FEE.fee_per_kvb.value() > int64_t{0});
    CHECK(primitives::DEFAULT_FALLBACK_FEE > primitives::DEFAULT_MIN_RELAY_FEE);

    // to_string is non-empty.
    CHECK(!low.to_string().empty());
}

// ===========================================================================
// Address
// ===========================================================================

TEST_CASE(Address, default_and_validity) {
    // Default-constructed address is invalid.
    primitives::Address addr;
    CHECK(!addr.is_valid());
    CHECK_EQ(addr.type(), primitives::AddressType::UNKNOWN);
}

TEST_CASE(Address, from_string_invalid) {
    // Garbage string must fail.
    auto r1 = primitives::Address::from_string("not_a_valid_address");
    CHECK_ERR(r1);

    // Empty string must fail.
    auto r2 = primitives::Address::from_string("");
    CHECK_ERR(r2);
}

TEST_CASE(Address, from_pubkey_hash_roundtrip) {
    // Construct a P2PKH address from a known 20-byte hash.
    core::uint160 hash = core::uint160::from_hex(
        "0000000000000000000000000000000000000001");
    primitives::Address addr =
        primitives::Address::from_pubkey_hash(hash, "fc");

    CHECK(addr.is_valid());
    CHECK_EQ(addr.type(), primitives::AddressType::P2PKH);
    CHECK(!addr.to_string().empty());

    // Parse the encoded string back and compare.
    auto parsed = primitives::Address::from_string(addr.to_string(), "fc");
    CHECK_OK(parsed);
    CHECK(parsed.value() == addr);
}

