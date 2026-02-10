// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner/difficulty.h"

#include "core/logging.h"
#include "core/types.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>

namespace miner {

// ---------------------------------------------------------------------------
// bits_to_target
// ---------------------------------------------------------------------------

core::uint256 bits_to_target(uint32_t bits) {
    // Extract exponent and mantissa from the compact representation.
    uint32_t exponent = (bits >> 24) & 0xFF;
    uint32_t mantissa = bits & 0x7FFFFF;
    bool negative = (bits & 0x800000) != 0;

    // A negative target or zero mantissa yields a zero target.
    if (negative || mantissa == 0) {
        return core::uint256{};
    }

    // Build the target: mantissa * 2^(8 * (exponent - 3)).
    // The mantissa occupies the top 3 bytes of the target at the position
    // determined by the exponent.
    //
    // We work in a 32-byte little-endian array (matching uint256 internal
    // representation).
    std::array<uint8_t, 32> target_bytes{};

    if (exponent <= 3) {
        // The mantissa is right-shifted so only the low (exponent) bytes
        // are significant.
        uint32_t shifted = mantissa >> (8 * (3 - exponent));
        target_bytes[0] = static_cast<uint8_t>(shifted & 0xFF);
        if (exponent >= 2) {
            target_bytes[1] = static_cast<uint8_t>((shifted >> 8) & 0xFF);
        }
        if (exponent >= 3) {
            target_bytes[2] = static_cast<uint8_t>((shifted >> 16) & 0xFF);
        }
    } else {
        // Place the 3 mantissa bytes starting at byte offset (exponent - 3)
        // in the little-endian representation.
        uint32_t byte_offset = exponent - 3;
        if (byte_offset < 32) {
            target_bytes[byte_offset] = static_cast<uint8_t>(mantissa & 0xFF);
        }
        if (byte_offset + 1 < 32) {
            target_bytes[byte_offset + 1] =
                static_cast<uint8_t>((mantissa >> 8) & 0xFF);
        }
        if (byte_offset + 2 < 32) {
            target_bytes[byte_offset + 2] =
                static_cast<uint8_t>((mantissa >> 16) & 0xFF);
        }
    }

    return core::uint256::from_bytes(
        std::span<const uint8_t, 32>(target_bytes.data(), 32));
}

// ---------------------------------------------------------------------------
// target_to_bits
// ---------------------------------------------------------------------------

uint32_t target_to_bits(const core::uint256& target) {
    // The uint256 stores bytes in little-endian order.
    // Find the most significant non-zero byte.
    const auto& bytes = target.bytes();
    int msb_index = 31;
    while (msb_index >= 0 && bytes[msb_index] == 0) {
        --msb_index;
    }

    if (msb_index < 0) {
        // Target is zero.
        return 0;
    }

    // The exponent is the number of bytes needed to represent the value.
    uint32_t exponent = static_cast<uint32_t>(msb_index + 1);

    // Extract the top 3 bytes as the mantissa.
    uint32_t mantissa = 0;
    if (msb_index >= 2) {
        mantissa = (static_cast<uint32_t>(bytes[msb_index]) << 16) |
                   (static_cast<uint32_t>(bytes[msb_index - 1]) << 8) |
                   static_cast<uint32_t>(bytes[msb_index - 2]);
    } else if (msb_index >= 1) {
        mantissa = (static_cast<uint32_t>(bytes[msb_index]) << 16) |
                   (static_cast<uint32_t>(bytes[msb_index - 1]) << 8);
    } else {
        mantissa = static_cast<uint32_t>(bytes[msb_index]) << 16;
    }

    // If the high bit of the mantissa is set, we need to add an extra byte
    // to the exponent to avoid the sign bit being interpreted as negative.
    if (mantissa & 0x800000) {
        mantissa >>= 8;
        exponent += 1;
    }

    return (exponent << 24) | (mantissa & 0x7FFFFF);
}

// ---------------------------------------------------------------------------
// calculate_next_work_required
// ---------------------------------------------------------------------------

uint32_t calculate_next_work_required(
    const chain::BlockIndex& last_block,
    const chain::BlockIndex& first_block,
    const consensus::ConsensusParams& params) {

    // Calculate the actual timespan of the difficulty period.
    int64_t actual_timespan =
        static_cast<int64_t>(last_block.time) -
        static_cast<int64_t>(first_block.time);

    // Clamp the actual timespan to [target_timespan/4, target_timespan*4].
    // This prevents extreme difficulty swings.
    int64_t target_timespan = params.pow_target_timespan;
    int64_t min_timespan = target_timespan / 4;
    int64_t max_timespan = target_timespan * 4;

    actual_timespan = std::clamp(actual_timespan, min_timespan, max_timespan);

    LOG_DEBUG(core::LogCategory::MINING,
        "Difficulty adjustment: actual_timespan=" +
        std::to_string(actual_timespan) +
        "s target_timespan=" +
        std::to_string(target_timespan) + "s");

    // Compute the new target:
    //   new_target = old_target * actual_timespan / target_timespan
    //
    // We use the full uint256 arithmetic to avoid overflow.
    core::uint256 new_target = bits_to_target(last_block.bits);

    // Multiply by actual_timespan.
    new_target *= static_cast<uint64_t>(actual_timespan);

    // Divide by target_timespan.
    new_target /= static_cast<uint64_t>(target_timespan);

    // Ensure the new target does not exceed the proof-of-work limit.
    if (new_target > params.pow_limit) {
        new_target = params.pow_limit;
    }

    uint32_t new_bits = target_to_bits(new_target);

    LOG_INFO(core::LogCategory::MINING,
        "New difficulty bits: 0x" +
        std::to_string(new_bits) +
        " difficulty=" +
        std::to_string(get_difficulty(new_bits)));

    return new_bits;
}

// ---------------------------------------------------------------------------
// get_difficulty
// ---------------------------------------------------------------------------

double get_difficulty(uint32_t bits) {
    // Difficulty is the ratio of the maximum possible target (at minimum
    // difficulty) to the current target.
    //
    // For human-readable display, we compute:
    //   difficulty = max_target_mantissa * 2^(max_exponent - 3)
    //               / (mantissa * 2^(exponent - 3))
    //
    // Using the standard genesis difficulty with bits = 0x1d00ffff
    // (Bitcoin convention), difficulty 1.0 corresponds to that target.
    //
    // Simplified: difficulty = 0x00ffff * 2^(26*8) / (mantissa * 2^(8*(exp-3)))

    uint32_t exponent = (bits >> 24) & 0xFF;
    uint32_t mantissa = bits & 0x00FFFFFF;

    if (mantissa == 0) {
        return 0.0;
    }

    // Handle sign bit.
    if (mantissa & 0x800000) {
        return 0.0;
    }

    // Reference difficulty-1 target: 0x00ffff * 2^(8*(0x1d - 3))
    // = 0x00ffff * 2^208
    //
    // Current target: mantissa * 2^(8*(exponent - 3))
    //
    // difficulty = (0x00ffff * 2^208) / (mantissa * 2^(8*(exponent-3)))
    //           = (0x00ffff / mantissa) * 2^(208 - 8*(exponent-3))
    //           = (0x00ffff / mantissa) * 2^(8*(26-exponent) + 8*3 - 208)
    // Simplifying: exponent of 2 = 8 * (0x1d - exponent)

    double mantissa_ratio = static_cast<double>(0x00FFFF) /
                            static_cast<double>(mantissa);

    int shift = 8 * (static_cast<int>(0x1D) - static_cast<int>(exponent));

    return mantissa_ratio * std::pow(2.0, static_cast<double>(shift));
}

// ---------------------------------------------------------------------------
// estimate_hashrate
// ---------------------------------------------------------------------------

double estimate_hashrate(double difficulty, double block_time) {
    if (block_time <= 0.0) {
        return 0.0;
    }

    // The expected number of hashes to find a block at difficulty D is:
    //   D * 2^32
    // The hashrate is that divided by the average block time.
    //
    // For keccak256d one hash evaluation equals one nonce attempt.

    return difficulty * 4294967296.0 / block_time;
}

// ---------------------------------------------------------------------------
// get_block_proof
// ---------------------------------------------------------------------------

core::uint256 get_block_proof(uint32_t bits) {
    core::uint256 target = bits_to_target(bits);

    if (target.is_zero()) {
        return core::uint256{};
    }

    // Work = 2^256 / (target + 1)
    //
    // We compute this as: (~target / (target + 1)) + 1
    // which avoids the need for 2^256 directly.

    core::uint256 one{};
    one.data()[0] = 1;

    // target + 1: add 1 to the target
    core::uint256 target_plus_one = target;
    // Simple add-1 on LE bytes
    bool carry = true;
    for (size_t i = 0; i < 32 && carry; ++i) {
        uint16_t sum = static_cast<uint16_t>(target_plus_one.data()[i]) + 1;
        target_plus_one.data()[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = (sum >> 8) != 0;
    }

    if (target_plus_one.is_zero()) {
        // target was max uint256, target+1 overflowed to zero.
        // Work would be 1.
        return one;
    }

    // ~target = bitwise NOT (manual, since Blob::operator~ returns Blob<N>)
    core::uint256 not_target;
    for (size_t i = 0; i < 32; ++i) {
        not_target.data()[i] = ~target.data()[i];
    }

    // Division: not_target / target_plus_one
    // We use the scalar division available on uint256 if target+1 fits in 64 bits.
    // For a proper implementation, we'll do byte-level long division.

    // Since this is used for chain_work accumulation, and the target is typically
    // representable in a reasonable range, we compute it correctly.
    // For simplicity and correctness, we convert to double for an approximation
    // and then construct the uint256. However, for production code we need
    // exact uint256 division.

    // Use a manual 256-bit division algorithm.
    // Dividend: not_target, Divisor: target_plus_one
    // Result: quotient

    // Convert not_target to BE, target_plus_one to BE,
    // perform division in BE, convert result back to LE.

    // Helper: reverse bytes for BE <-> LE conversion.
    auto reverse_bytes = [](const std::array<uint8_t, 32>& src) {
        std::array<uint8_t, 32> dst;
        for (int i = 0; i < 32; ++i) {
            dst[i] = src[31 - i];
        }
        return dst;
    };

    auto be_dividend = reverse_bytes(not_target.bytes());
    auto be_divisor = reverse_bytes(target_plus_one.bytes());

    // Long division in big-endian representation.
    std::array<uint8_t, 32> be_quotient{};
    std::array<uint8_t, 32> be_remainder{};

    for (int bit = 0; bit < 256; ++bit) {
        // Shift remainder left by 1 (BE: shift bytes left means shift to lower indices).
        for (int i = 0; i < 31; ++i) {
            be_remainder[i] = static_cast<uint8_t>(
                (be_remainder[i] << 1) |
                ((be_remainder[i + 1] >> 7) & 1));
        }
        be_remainder[31] = static_cast<uint8_t>(be_remainder[31] << 1);

        // Bring down the next bit from the dividend.
        int byte_idx = bit / 8;
        int bit_idx = 7 - (bit % 8);
        uint8_t dividend_bit = (be_dividend[byte_idx] >> bit_idx) & 1;
        be_remainder[31] |= dividend_bit;

        // Compare remainder >= divisor.
        bool ge = false;
        bool determined = false;
        for (int i = 0; i < 32; ++i) {
            if (be_remainder[i] > be_divisor[i]) {
                ge = true;
                determined = true;
                break;
            } else if (be_remainder[i] < be_divisor[i]) {
                ge = false;
                determined = true;
                break;
            }
        }
        if (!determined) {
            ge = true; // equal
        }

        if (ge) {
            // Set quotient bit.
            int q_byte = bit / 8;
            int q_bit = 7 - (bit % 8);
            be_quotient[q_byte] |= static_cast<uint8_t>(1 << q_bit);

            // Subtract divisor from remainder.
            uint16_t borrow = 0;
            for (int i = 31; i >= 0; --i) {
                uint16_t sub = static_cast<uint16_t>(be_remainder[i]) -
                               static_cast<uint16_t>(be_divisor[i]) - borrow;
                be_remainder[i] = static_cast<uint8_t>(sub & 0xFF);
                borrow = (sub >> 15) & 1;  // borrow if underflow
            }
        }
    }

    // Convert quotient back to LE.
    auto le_quotient = reverse_bytes(be_quotient);

    // Build the result: quotient + 1
    auto result = core::uint256::from_bytes(
        std::span<const uint8_t, 32>(le_quotient.data(), 32));

    // Add 1.
    carry = true;
    for (size_t i = 0; i < 32 && carry; ++i) {
        uint16_t sum = static_cast<uint16_t>(result.data()[i]) + 1;
        result.data()[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = (sum >> 8) != 0;
    }

    return result;
}

// ---------------------------------------------------------------------------
// check_proof_of_work
// ---------------------------------------------------------------------------

bool check_proof_of_work(
    const core::uint256& hash,
    uint32_t bits,
    const consensus::ConsensusParams& params) {

    core::uint256 target = bits_to_target(bits);

    // The target must not exceed the proof-of-work limit.
    if (target.is_zero() || target > params.pow_limit) {
        return false;
    }

    // The block hash must be less than or equal to the target.
    return hash <= target;
}

} // namespace miner
