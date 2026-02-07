#pragma once
// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ---------------------------------------------------------------------------
// Consensus-level amount validation
// ---------------------------------------------------------------------------
// Thin wrappers that check monetary values against the consensus money
// supply rules.  These are separate from the primitives::Amount class so
// that low-level code can construct Amount objects without pulling in
// consensus-layer dependencies.
// ---------------------------------------------------------------------------

#include "primitives/amount.h"

#include <cstdint>

namespace consensus {

/// Number of base units (satoshis) per coin -- re-exported from
/// primitives::Amount for convenience in consensus code.
constexpr int64_t COIN = primitives::Amount::COIN;

/// Maximum monetary value that may exist on the network, in base units.
/// 21,000,000 FTC * 100,000,000 satoshis/FTC.
constexpr int64_t MAX_MONEY = 21'000'000 * primitives::Amount::COIN;

/// Returns true if @p amount is within the valid consensus money range
/// [0, MAX_MONEY].  Negative values are never valid.
[[nodiscard]] bool check_money_range(primitives::Amount amount);

} // namespace consensus
