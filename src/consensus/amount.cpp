// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/amount.h"

namespace consensus {

bool check_money_range(primitives::Amount amount) {
    return amount.value() >= 0 && amount.value() <= MAX_MONEY;
}

} // namespace consensus
