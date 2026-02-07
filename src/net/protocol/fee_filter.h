#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core/error.h"

#include <cstdint>
#include <span>
#include <vector>

namespace net::protocol {

// ---------------------------------------------------------------------------
// Protocol constants for fee filter messages
// ---------------------------------------------------------------------------

/// Size of the feefilter message payload: a single 64-bit fee rate.
inline constexpr size_t FEE_FILTER_PAYLOAD_SIZE = 8;

/// Maximum acceptable fee rate (1 BTC/kvB = 100,000,000 sat/kvB).
/// Fee rates above this threshold are considered unreasonable and rejected
/// during validation.
inline constexpr int64_t MAX_FEE_FILTER_RATE = 100'000'000LL;

// ---------------------------------------------------------------------------
// FeeFilterMessage -- minimum fee rate filter (BIP133, FEEFILTER command)
// ---------------------------------------------------------------------------
// The feefilter message tells the receiving peer not to relay transactions
// to the sender whose fee rate falls below the specified minimum.  This
// helps reduce bandwidth waste by avoiding the transmission and subsequent
// rejection of transactions that would not pass the sender's mempool policy.
//
// The fee rate is expressed in satoshis per kilovirtual byte (sat/kvB):
//   fee_rate = (tx_fee_in_satoshis * 1000) / tx_vsize_in_vbytes
//
// A value of zero means "relay all transactions" (no minimum fee).
//
// Wire format:
//   min_fee_rate   int64    (8 bytes LE)
//
// This message should be sent periodically whenever the node's minimum
// relay fee changes (e.g., when the mempool fills up or drains).  It is
// also sent once during the initial handshake after version/verack.
//
// BIP133: https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki
// ---------------------------------------------------------------------------
struct FeeFilterMessage {
    int64_t min_fee_rate = 0;  // minimum fee rate in sat/kvB

    /// Serialize the feefilter message payload (8 bytes: fee rate as LE i64).
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /// Deserialize a feefilter message from raw bytes.
    [[nodiscard]] static core::Result<FeeFilterMessage> deserialize(
        std::span<const uint8_t> data);

    /// Validate the fee rate (non-negative, within reasonable bounds).
    [[nodiscard]] core::Result<void> validate() const;

    /// Return true if this filter allows all transactions (fee_rate == 0).
    [[nodiscard]] bool allows_all() const noexcept;

    /// Check whether a transaction with the given fee rate (in sat/kvB)
    /// passes this filter.
    [[nodiscard]] bool passes(int64_t tx_fee_rate) const noexcept;

    /// Create a FeeFilterMessage with a specific fee rate.
    [[nodiscard]] static FeeFilterMessage with_rate(int64_t rate) noexcept;
};

} // namespace net::protocol
