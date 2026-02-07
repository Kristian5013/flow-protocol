// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_framework.h"

#include "wallet/coins.h"
#include "wallet/create_tx.h"
#include "wallet/spend.h"

// ===========================================================================
// Wallet :: CoinSelection
// ===========================================================================

TEST_CASE(Wallet, CoinSelectionDefaultConstruction) {
    wallet::CoinSelection sel;

    // A default-constructed CoinSelection should have an empty input set,
    // zero amounts, and no change flag.
    CHECK(sel.inputs.empty());
    CHECK_EQ(sel.total_in.value(), int64_t{0});
    CHECK_EQ(sel.fee.value(), int64_t{0});
    CHECK_EQ(sel.change.value(), int64_t{0});
    CHECK_EQ(sel.has_change, false);
}

TEST_CASE(Wallet, CoinSelectionProperties) {
    wallet::CoinSelection sel;
    sel.total_in = primitives::Amount(50000);
    sel.fee      = primitives::Amount(1000);
    sel.change   = primitives::Amount(9000);
    sel.has_change = true;

    CHECK_EQ(sel.total_in.value(), int64_t{50000});
    CHECK_EQ(sel.fee.value(), int64_t{1000});
    CHECK_EQ(sel.change.value(), int64_t{9000});
    CHECK(sel.has_change);
}

// ===========================================================================
// Wallet :: Recipient
// ===========================================================================

TEST_CASE(Wallet, RecipientConstruction) {
    wallet::Recipient r;
    r.address = "fc1qexampleaddress";
    r.amount  = primitives::Amount(100000);
    r.subtract_fee = true;

    CHECK_EQ(r.address, std::string("fc1qexampleaddress"));
    CHECK_EQ(r.amount.value(), int64_t{100000});
    CHECK(r.subtract_fee);

    // Default subtract_fee should be false.
    wallet::Recipient r2;
    r2.address = "fc1qother";
    r2.amount  = primitives::Amount(200000);
    CHECK_EQ(r2.subtract_fee, false);
}

// ===========================================================================
// Wallet :: estimate_tx_size
// ===========================================================================

TEST_CASE(Wallet, EstimateTxSize) {
    // A transaction with 1 input and 1 output should have a reasonable size.
    size_t size_1_1 = wallet::estimate_tx_size(1, 1);
    CHECK(size_1_1 > 0);

    // More inputs/outputs should produce a larger estimated size.
    size_t size_2_2 = wallet::estimate_tx_size(2, 2);
    CHECK(size_2_2 > size_1_1);

    size_t size_5_3 = wallet::estimate_tx_size(5, 3);
    CHECK(size_5_3 > size_2_2);

    // Zero inputs / zero outputs should still return a non-negative value
    // (the overhead of the transaction structure itself).
    size_t size_0_0 = wallet::estimate_tx_size(0, 0);
    CHECK(size_0_0 < size_1_1);
}

// ===========================================================================
// Wallet :: total_send_amount
// ===========================================================================

TEST_CASE(Wallet, TotalSendAmount) {
    // Empty recipient list: total should be zero.
    std::vector<wallet::Recipient> empty;
    primitives::Amount total_empty = wallet::total_send_amount(empty);
    CHECK_EQ(total_empty.value(), int64_t{0});

    // Single recipient.
    std::vector<wallet::Recipient> single;
    single.push_back({"addr1", primitives::Amount(50000), false});
    primitives::Amount total_single = wallet::total_send_amount(single);
    CHECK_EQ(total_single.value(), int64_t{50000});

    // Multiple recipients: amounts should add up.
    std::vector<wallet::Recipient> multi;
    multi.push_back({"addr1", primitives::Amount(10000), false});
    multi.push_back({"addr2", primitives::Amount(20000), false});
    multi.push_back({"addr3", primitives::Amount(30000), true});
    primitives::Amount total_multi = wallet::total_send_amount(multi);
    CHECK_EQ(total_multi.value(), int64_t{60000});
}
