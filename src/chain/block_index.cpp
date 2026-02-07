// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/block_index.h"

#include "core/types.h"
#include "primitives/block_header.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

namespace chain {

// ---------------------------------------------------------------------------
// is_valid
// ---------------------------------------------------------------------------
bool BlockIndex::is_valid(Status up_to) const {
    // A failed block is never valid regardless of the recorded level.
    if (status & BLOCK_FAILED_MASK) {
        return false;
    }
    return (status & BLOCK_VALID_MASK) >= static_cast<uint32_t>(up_to);
}

// ---------------------------------------------------------------------------
// raise_validity
// ---------------------------------------------------------------------------
void BlockIndex::raise_validity(Status up_to) {
    // Do not raise validity on a block that has already been marked as failed.
    if (status & BLOCK_FAILED_MASK) {
        return;
    }
    if ((status & BLOCK_VALID_MASK) < static_cast<uint32_t>(up_to)) {
        status = (status & ~BLOCK_VALID_MASK) | static_cast<uint32_t>(up_to);
    }
}

// ---------------------------------------------------------------------------
// get_ancestor  (mutable)
// ---------------------------------------------------------------------------
BlockIndex* BlockIndex::get_ancestor(int target_height) {
    if (target_height < 0 || target_height > height) {
        return nullptr;
    }

    BlockIndex* walk = this;
    while (walk != nullptr && walk->height != target_height) {
        walk = walk->prev;
    }
    return walk;
}

// ---------------------------------------------------------------------------
// get_ancestor  (const)
// ---------------------------------------------------------------------------
const BlockIndex* BlockIndex::get_ancestor(int target_height) const {
    if (target_height < 0 || target_height > height) {
        return nullptr;
    }

    const BlockIndex* walk = this;
    while (walk != nullptr && walk->height != target_height) {
        walk = walk->prev;
    }
    return walk;
}

// ---------------------------------------------------------------------------
// get_block_work
// ---------------------------------------------------------------------------
// Computes  work = 2^256 / (target + 1).
//
// The target is decoded from the compact "bits" representation:
//   target = mantissa * 2^(8 * (exponent - 3))
// where exponent = bits >> 24, mantissa = bits & 0x007fffff.
// If the sign bit (0x00800000) is set the target is negative (invalid),
// but we treat that as zero work.
//
// We compute the division using the uint256 arithmetic already available
// in the codebase: ~target / (target + 1) + 1, which equals
// (2^256 - 1 - target) / (target + 1) + 1 = 2^256 / (target + 1)
// (integer division, same trick used in Bitcoin Core).
// ---------------------------------------------------------------------------
core::uint256 BlockIndex::get_block_work() const {
    // Decode compact bits into a uint256 target.
    uint32_t compact = bits;
    uint32_t exponent = compact >> 24;
    uint32_t mantissa = compact & 0x007fffffU;
    bool negative = (compact & 0x00800000U) != 0;

    // A zero mantissa or negative target yields zero work.
    if (mantissa == 0 || negative) {
        return core::uint256{};
    }

    // Build the target as a uint256.
    // target = mantissa * 2^(8*(exponent-3))
    // We construct it by placing the 3-byte mantissa at the correct position.
    core::uint256 target{};
    if (exponent <= 3) {
        // Shift mantissa right when exponent is small.
        mantissa >>= 8 * (3 - exponent);
        // Place the (possibly shifted) mantissa into the lowest bytes.
        target.data()[0] = static_cast<uint8_t>(mantissa & 0xff);
        target.data()[1] = static_cast<uint8_t>((mantissa >> 8) & 0xff);
        target.data()[2] = static_cast<uint8_t>((mantissa >> 16) & 0xff);
    } else {
        // Number of bytes to shift left from position 0.
        unsigned shift_bytes = exponent - 3;
        if (shift_bytes + 3 > 32) {
            // Target overflows uint256 -- effectively infinite difficulty zero.
            // Still return non-zero work (the hash matched, so work exists).
            // Use a minimal work value of 1.
            core::uint256 one{};
            one.data()[0] = 1;
            return one;
        }
        target.data()[shift_bytes + 0] = static_cast<uint8_t>(mantissa & 0xff);
        target.data()[shift_bytes + 1] = static_cast<uint8_t>((mantissa >> 8) & 0xff);
        target.data()[shift_bytes + 2] = static_cast<uint8_t>((mantissa >> 16) & 0xff);
    }

    // Avoid division by zero: if target is zero, return zero work.
    if (target.is_zero()) {
        return core::uint256{};
    }

    // work = (~target / (target + 1)) + 1
    // This is equivalent to 2^256 / (target + 1), using the identity
    // ~target = (2^256 - 1) - target.

    // Compute target_plus_one = target + 1 using byte arithmetic.
    core::uint256 target_plus_one = target;
    {
        uint16_t carry = 1;
        for (size_t i = 0; i < 32 && carry != 0; ++i) {
            uint16_t sum = static_cast<uint16_t>(target_plus_one.data()[i]) + carry;
            target_plus_one.data()[i] = static_cast<uint8_t>(sum & 0xff);
            carry = sum >> 8;
        }
    }

    // If target+1 overflowed to zero (target was all 0xff), work is 1.
    if (target_plus_one.is_zero()) {
        core::uint256 one{};
        one.data()[0] = 1;
        return one;
    }

    // Compute ~target (bitwise complement).
    core::uint256 not_target{};
    for (size_t i = 0; i < 32; ++i) {
        not_target.data()[i] = static_cast<uint8_t>(~target.data()[i]);
    }

    // Divide not_target by target_plus_one.
    // We use a simple long division: treat not_target as a 256-bit dividend
    // and target_plus_one as the divisor.  Since uint256 supports /= by
    // uint64_t but not by uint256, we implement a binary long division.
    //
    // However, the codebase's uint256 has operator/=(uint64_t) only.
    // For a full uint256-by-uint256 division we implement shift-and-subtract.

    // Binary long division: quotient = not_target / target_plus_one
    core::uint256 quotient{};
    core::uint256 remainder{};

    // Process bits from most significant to least significant.
    // The uint256 is stored in little-endian byte order, so bit 255 is the
    // MSB of byte 31, and bit 0 is the LSB of byte 0.
    for (int bit = 255; bit >= 0; --bit) {
        // Shift remainder left by 1.
        {
            uint8_t carry = 0;
            for (size_t i = 0; i < 32; ++i) {
                uint8_t new_carry = (remainder.data()[i] >> 7) & 1;
                remainder.data()[i] = static_cast<uint8_t>((remainder.data()[i] << 1) | carry);
                carry = new_carry;
            }
        }

        // Bring down the next bit from not_target.
        size_t byte_idx = static_cast<size_t>(bit / 8);
        int bit_idx = bit % 8;
        uint8_t next_bit = (not_target.data()[byte_idx] >> bit_idx) & 1;
        remainder.data()[0] |= next_bit;

        // If remainder >= target_plus_one, subtract and set quotient bit.
        if (remainder >= target_plus_one) {
            // remainder -= target_plus_one  (byte-level subtraction)
            uint16_t borrow = 0;
            for (size_t i = 0; i < 32; ++i) {
                uint16_t diff = static_cast<uint16_t>(remainder.data()[i])
                              - static_cast<uint16_t>(target_plus_one.data()[i])
                              - borrow;
                remainder.data()[i] = static_cast<uint8_t>(diff & 0xff);
                borrow = (diff >> 15) & 1;  // borrow if high bit set (negative)
            }

            // Set the corresponding bit in the quotient.
            quotient.data()[byte_idx] |= (1 << bit_idx);
        }
    }

    // work = quotient + 1
    {
        uint16_t carry = 1;
        for (size_t i = 0; i < 32 && carry != 0; ++i) {
            uint16_t sum = static_cast<uint16_t>(quotient.data()[i]) + carry;
            quotient.data()[i] = static_cast<uint8_t>(sum & 0xff);
            carry = sum >> 8;
        }
    }

    return quotient;
}

// ---------------------------------------------------------------------------
// get_median_time_past
// ---------------------------------------------------------------------------
int64_t BlockIndex::get_median_time_past() const {
    static constexpr int MEDIAN_TIME_SPAN = 11;

    std::array<int64_t, MEDIAN_TIME_SPAN> timestamps{};
    int count = 0;

    const BlockIndex* walk = this;
    while (walk != nullptr && count < MEDIAN_TIME_SPAN) {
        timestamps[static_cast<size_t>(count)] = static_cast<int64_t>(walk->time);
        ++count;
        walk = walk->prev;
    }

    std::sort(timestamps.begin(), timestamps.begin() + count);
    return timestamps[static_cast<size_t>(count / 2)];
}

// ---------------------------------------------------------------------------
// get_block_header
// ---------------------------------------------------------------------------
primitives::BlockHeader BlockIndex::get_block_header() const {
    primitives::BlockHeader header;
    header.version = version;
    header.merkle_root = hash_merkle_root;
    header.timestamp = time;
    header.bits = bits;
    header.nonce = nonce;

    // The prev_hash comes from the previous block's cached hash.
    if (prev != nullptr) {
        header.prev_hash = prev->block_hash;
    }
    // For genesis, prev_hash remains the default zero hash.

    return header;
}

// ---------------------------------------------------------------------------
// to_string
// ---------------------------------------------------------------------------
std::string BlockIndex::to_string() const {
    std::ostringstream oss;
    oss << "BlockIndex(hash=" << block_hash.to_hex()
        << ", height=" << height
        << ", version=" << version
        << ", time=" << time
        << ", bits=0x" << std::hex << bits << std::dec
        << ", nonce=" << nonce
        << ", tx_count=" << tx_count
        << ", status=0x" << std::hex << status << std::dec
        << ")";
    return oss.str();
}

} // namespace chain
