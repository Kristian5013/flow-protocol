// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/fees.h"

#include "primitives/script/script.h"
#include "primitives/script/standard.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

namespace primitives {

// =========================================================================
// FeeRate
// =========================================================================

Amount FeeRate::compute_fee(size_t vsize) const {
    if (vsize == 0) return Amount(0);

    int64_t rate = fee_per_kvb.value();
    if (rate == 0) return Amount(0);

    // fee = ceil(rate * vsize / 1000)
    // To avoid floating-point: fee = (rate * vsize + 999) / 1000
    // But we must be careful with overflow for very large transactions.
    // For any reasonable transaction (<= 4MB) and fee rate (<= 1 BTC/kvB),
    // rate * vsize fits comfortably in int64_t.
    int64_t sz = static_cast<int64_t>(vsize);

    if (rate > 0) {
        // Positive fee: round up
        int64_t fee = (rate * sz + 999) / 1000;
        // Fee should never be negative even with rounding
        return Amount(std::max<int64_t>(fee, 0));
    } else {
        // Negative fee rate (unusual but possible for priority adjustment):
        // round toward zero (less negative).
        int64_t fee = (rate * sz) / 1000;
        return Amount(fee);
    }
}

FeeRate FeeRate::from_fee_and_size(Amount fee, size_t vsize) {
    if (vsize == 0) return FeeRate(Amount(0));

    // rate_per_kvb = fee * 1000 / vsize
    int64_t rate = (fee.value() * 1000) / static_cast<int64_t>(vsize);
    return FeeRate(Amount(rate));
}

std::string FeeRate::to_string() const {
    // Convert from base-units/kvB to base-units/vB for display.
    // 1 kvB = 1000 vB, so sat/vB = fee_per_kvb / 1000.
    double sat_per_vb = static_cast<double>(fee_per_kvb.value()) / 1000.0;

    std::ostringstream oss;
    oss.precision(2);
    oss << std::fixed << sat_per_vb << " sat/vB";
    return oss.str();
}

// =========================================================================
// dust_threshold
// =========================================================================

Amount dust_threshold(const script::Script& script,
                      const FeeRate& dust_relay_fee) {
    // The dust threshold is the cost to create + spend an output.
    //
    // Creation cost: the output itself is serialized as:
    //   8 (amount) + compact_size(script_len) + script_len
    //
    // Spending cost depends on the input type:
    //
    // For a txin, the base overhead is:
    //   32 (prevhash) + 4 (index) + compact_size(scriptSig) + 4 (sequence)
    //   = 41 bytes (with empty scriptSig for segwit)
    //
    // The additional spending cost varies by script type.

    size_t script_size = script.size();

    // Output serialized size: 8 + varint(script_size) + script_size
    size_t output_size = 8;
    if (script_size < 253) {
        output_size += 1;
    } else if (script_size < 65536) {
        output_size += 3;
    } else {
        output_size += 5;
    }
    output_size += script_size;

    // Estimate the spending input virtual size based on script type.
    size_t spend_vsize = 0;

    auto type = script::classify(script);
    switch (type) {
        case script::TxoutType::PUBKEYHASH:
            // P2PKH input: 32+4+1+107+4 = 148 bytes
            // scriptSig = <73 sig> <33 pubkey> = ~107 bytes
            spend_vsize = 148;
            break;

        case script::TxoutType::SCRIPTHASH:
            // P2SH-P2WPKH input (most common P2SH spend):
            //   base: 32+4+1+23+4 = 64 bytes
            //   witness: ~107 bytes (at 1/4 weight)
            //   vsize ~= 64 + 107/4 ~= 91
            spend_vsize = 91;
            break;

        case script::TxoutType::WITNESS_V0_KEYHASH:
            // P2WPKH input:
            //   base: 32+4+1+0+4 = 41 bytes
            //   witness: 1+73+1+33 = 108 bytes (at 1/4 weight)
            //   vsize = (41*4 + 108 + 3) / 4 = 68
            spend_vsize = 68;
            break;

        case script::TxoutType::WITNESS_V0_SCRIPTHASH:
            // P2WSH input (single-sig witness script):
            //   base: 41 bytes
            //   witness: ~252 bytes (at 1/4 weight)
            //   vsize ~= (41*4 + 252 + 3) / 4 = 104
            spend_vsize = 104;
            break;

        case script::TxoutType::WITNESS_V1_TAPROOT:
            // P2TR key-path spend:
            //   base: 41 bytes
            //   witness: 1+65 = 66 bytes (Schnorr sig)
            //   vsize = (41*4 + 66 + 3) / 4 = 58
            spend_vsize = 58;
            break;

        case script::TxoutType::PUBKEY:
            // Bare pubkey: scriptSig = <73 sig> = 74 bytes
            //   32+4+1+74+4 = 115 bytes
            spend_vsize = 115;
            break;

        case script::TxoutType::MULTISIG:
        case script::TxoutType::NULL_DATA:
        case script::TxoutType::WITNESS_UNKNOWN:
        case script::TxoutType::NONSTANDARD:
        default:
            // Conservative estimate for unknown types:
            // 32 (prevhash) + 4 (index) + 1 (varint) +
            // script_size (redeemScript push) + 4 (sequence)
            spend_vsize = 32 + 4 + 1 + script_size + 4;
            break;
    }

    // Total virtual size for dust calculation:
    // The output creation cost plus the spending input cost.
    size_t total_vsize = output_size + spend_vsize;

    // The dust threshold is the fee cost to create and spend the output.
    // If the output value is less than this cost, it's dust.
    Amount fee = dust_relay_fee.compute_fee(total_vsize);

    // Ensure threshold is at least 1 base unit for non-unspendable outputs
    if (fee.value() <= 0 && type != script::TxoutType::NULL_DATA) {
        return Amount(1);
    }

    return fee;
}

} // namespace primitives
