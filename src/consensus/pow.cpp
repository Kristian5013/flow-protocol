// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/pow.h"
#include "consensus/params.h"
#include "core/logging.h"
#include "core/types.h"
#include "crypto/equihash.h"
#include "primitives/block_header.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace consensus {

// ---------------------------------------------------------------------------
// nbits_to_target  --  compact nBits -> uint256
// ---------------------------------------------------------------------------
// Compact format (Bitcoin-style):
//   uint32_t nbits = (exponent << 24) | mantissa
//   exponent = number of bytes in the resulting target
//   mantissa = 3-byte big-endian significand (bytes 1-3 of nbits)
//   target   = mantissa * 2^(8 * (exponent - 3))
//
// Internal storage in Blob<32> is LITTLE-ENDIAN (byte 0 = least significant).
// ---------------------------------------------------------------------------

core::uint256 nbits_to_target(uint32_t nbits) {
    // Extract fields.
    uint32_t exponent = nbits >> 24;
    uint32_t mantissa = nbits & 0x007FFFFF;
    bool negative = (nbits & 0x00800000) != 0;

    // A negative target is invalid for PoW -- return zero.
    if (negative && mantissa != 0) {
        return core::uint256{};
    }

    // Zero mantissa -> zero target regardless of exponent.
    if (mantissa == 0) {
        return core::uint256{};
    }

    // Build the target in a zeroed 32-byte little-endian buffer.
    //
    // The target value is:  mantissa * 2^(8*(exponent-3))
    //
    // Mantissa bytes:
    //   m0 = mantissa & 0xFF          (least significant)
    //   m1 = (mantissa >> 8) & 0xFF
    //   m2 = (mantissa >> 16) & 0xFF  (most significant)
    //
    // In LE storage (index 0 = LSB), the mantissa occupies:
    //   LE index (exponent - 3) = m0
    //   LE index (exponent - 2) = m1
    //   LE index (exponent - 1) = m2

    std::array<uint8_t, 32> buf{};

    if (exponent <= 3) {
        // The mantissa is shifted RIGHT by 8*(3-exponent) bits, meaning
        // we lose the least-significant bytes of the mantissa.
        uint32_t shift = 3 - exponent;
        uint32_t shifted = mantissa >> (8 * shift);
        // Place in LE: the result fits in the first few bytes.
        buf[0] = static_cast<uint8_t>(shifted & 0xFF);
        if (exponent >= 2) {
            buf[1] = static_cast<uint8_t>((shifted >> 8) & 0xFF);
        }
        if (exponent >= 3) {
            buf[2] = static_cast<uint8_t>((shifted >> 16) & 0xFF);
        }
    } else {
        // Place the 3 mantissa bytes at their LE positions.
        // In LE storage, index 0 = least significant byte.
        // The mantissa value occupies bytes at LE positions:
        //   base     = exponent - 3  (m0, least significant byte of mantissa)
        //   base + 1 = exponent - 2  (m1)
        //   base + 2 = exponent - 1  (m2, most significant byte of mantissa)
        uint32_t base = exponent - 3;
        if (base < 32) {
            buf[base] = static_cast<uint8_t>(mantissa & 0xFF);
        }
        if (base + 1 < 32) {
            buf[base + 1] = static_cast<uint8_t>((mantissa >> 8) & 0xFF);
        }
        if (base + 2 < 32) {
            buf[base + 2] = static_cast<uint8_t>((mantissa >> 16) & 0xFF);
        }
    }

    return core::uint256::from_bytes(std::span<const uint8_t, 32>(buf));
}

// ---------------------------------------------------------------------------
// target_to_nbits  --  uint256 -> compact nBits
// ---------------------------------------------------------------------------

uint32_t target_to_nbits(const core::uint256& target) {
    // Work in little-endian byte order (native Blob<32> storage).
    const uint8_t* data = target.data();

    // Find the position of the most-significant non-zero byte in LE layout.
    // LE index 31 is the most significant byte.
    int msb_index = -1;
    for (int i = 31; i >= 0; --i) {
        if (data[i] != 0) {
            msb_index = i;
            break;
        }
    }

    // Target is zero.
    if (msb_index < 0) {
        return 0;
    }

    // The exponent in the compact encoding is the number of bytes needed.
    // That equals (msb_index + 1) in our LE representation.
    uint32_t exponent = static_cast<uint32_t>(msb_index + 1);

    // Extract the top 3 bytes as the mantissa (big-endian within the uint32).
    // In LE storage: the most significant byte is at msb_index,
    // next at msb_index-1, then msb_index-2.
    uint32_t mantissa = 0;
    if (exponent >= 3) {
        mantissa = (static_cast<uint32_t>(data[msb_index]) << 16)
                 | (static_cast<uint32_t>(data[msb_index - 1]) << 8)
                 | (static_cast<uint32_t>(data[msb_index - 2]));
    } else if (exponent == 2) {
        mantissa = (static_cast<uint32_t>(data[msb_index]) << 16)
                 | (static_cast<uint32_t>(data[msb_index - 1]) << 8);
    } else {
        // exponent == 1
        mantissa = static_cast<uint32_t>(data[msb_index]) << 16;
    }

    // If the high bit of the mantissa is set, we need to shift right by 8
    // bits and bump the exponent by 1, because the high bit is reserved for
    // the sign in Bitcoin's compact encoding.
    if (mantissa & 0x00800000) {
        mantissa >>= 8;
        exponent += 1;
    }

    return (exponent << 24) | (mantissa & 0x007FFFFF);
}

// ---------------------------------------------------------------------------
// check_proof_of_work
// ---------------------------------------------------------------------------

bool check_proof_of_work(const core::uint256& hash,
                         uint32_t nbits,
                         const ConsensusParams& params) {
    // Decode the compact target.
    core::uint256 target = nbits_to_target(nbits);

    // A zero target is always invalid.
    if (target.is_zero()) {
        LOG_DEBUG(core::LogCategory::VALIDATION,
                  "check_proof_of_work: nbits decodes to zero target");
        return false;
    }

    // Target must not exceed the network's proof-of-work limit.
    if (target > params.pow_limit) {
        LOG_DEBUG(core::LogCategory::VALIDATION,
                  "check_proof_of_work: target " + target.to_hex()
                  + " exceeds pow_limit " + params.pow_limit.to_hex());
        return false;
    }

    // The block hash must be at or below the target.
    if (hash > target) {
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// get_next_work_required
// ---------------------------------------------------------------------------

uint32_t get_next_work_required(int height,
                                int64_t last_block_time,
                                int64_t first_block_time,
                                uint32_t last_nbits,
                                const ConsensusParams& params) {
    // If not on a retarget boundary, keep the same difficulty.
    // difficulty_adjustment_interval() returns pow_target_timespan / pow_target_spacing.
    if (height % params.difficulty_adjustment_interval() != 0) {
        return last_nbits;
    }

    // Compute the actual timespan of the last 2016 blocks.
    int64_t actual_timespan = last_block_time - first_block_time;

    // Clamp to [pow_target_timespan / 4, pow_target_timespan * 4].
    int64_t min_timespan = params.pow_target_timespan / 4;
    int64_t max_timespan = params.pow_target_timespan * 4;
    actual_timespan = std::clamp(actual_timespan, min_timespan, max_timespan);

    // Compute new target: old_target * actual_timespan / pow_target_timespan.
    core::uint256 new_target = nbits_to_target(last_nbits);

    // Perform the multiplication and division using uint256 scalar arithmetic.
    // uint256 supports operator*=(uint64_t) and operator/=(uint64_t).
    new_target *= static_cast<uint64_t>(actual_timespan);
    new_target /= static_cast<uint64_t>(params.pow_target_timespan);

    // Clamp to pow_limit.
    if (new_target > params.pow_limit) {
        new_target = params.pow_limit;
    }

    return target_to_nbits(new_target);
}

// ---------------------------------------------------------------------------
// check_equihash_solution
// ---------------------------------------------------------------------------

bool check_equihash_solution(const primitives::BlockHeader& header,
                             const ConsensusParams& params) {
    // Serialize the 80-byte block header as the Equihash puzzle input.
    auto header_bytes = header.serialize_array();
    std::span<const uint8_t> input(header_bytes.data(), header_bytes.size());

    // Build Equihash parameters from the consensus config.
    crypto::EquihashParams eq_params;
    eq_params.n = static_cast<unsigned>(params.equihash_n);
    eq_params.k = static_cast<unsigned>(params.equihash_k);

    // The solution is expected to be carried externally (e.g. in an extended
    // block header field).  For the base 80-byte header format, the nonce is
    // part of the header and the solution must be supplied separately.
    // In FTC's wire format the Equihash solution is appended after the
    // standard 80-byte header.  At this layer we verify only the header
    // bytes; the caller is responsible for extracting the solution.
    //
    // For the base verification API we pass an empty solution span to
    // detect structural issues.  A full-node integration will provide the
    // actual solution bytes.
    //
    // NOTE: This function currently verifies the header commitment.  The
    // solution bytes are expected to be validated at a higher layer that
    // has access to the full serialised block (including the appended
    // Equihash solution field).  When that integration is wired up, the
    // solution parameter below will be replaced with the real data.

    // For now, we verify with the understanding that the caller provides
    // the solution embedded in the block data.  The minimal stub returns
    // true for the header-only check so that PoW validation can proceed
    // using the hash-based check (check_proof_of_work) as the primary
    // gate.  Full Equihash verification is performed at the block
    // deserialization layer.

    // TODO(consensus): Wire up the extended header solution field once the
    // block serialisation format is finalised.  For now, always delegate to
    // the hash-based PoW check.

    // Placeholder: verify with empty solution returns false for real blocks,
    // which is correct -- callers must use the overload that supplies the
    // solution bytes.  However, to keep the API usable during development
    // we log and return the result.
    std::vector<uint8_t> empty_solution;
    bool valid = crypto::equihash_verify(
        eq_params, input,
        std::span<const uint8_t>(empty_solution.data(),
                                 empty_solution.size()));

    if (!valid) {
        LOG_DEBUG(core::LogCategory::VALIDATION,
                  "check_equihash_solution: Equihash verification failed for "
                  "block " + header.hash().to_hex());
    }

    return valid;
}

}  // namespace consensus
