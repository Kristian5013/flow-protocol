// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/siphash.h"

#include <cstring>

namespace crypto {

// ===================================================================
// SipHash-2-4 internals
// ===================================================================

namespace {

/// Left-rotate a 64-bit word by @p n bits.
inline uint64_t rotl64(uint64_t x, int n) noexcept {
    return (x << n) | (x >> (64 - n));
}

/// One SipRound transformation on the four state words.
inline void sip_round(uint64_t& v0, uint64_t& v1,
                      uint64_t& v2, uint64_t& v3) noexcept {
    v0 += v1;
    v1 = rotl64(v1, 13);
    v1 ^= v0;
    v0 = rotl64(v0, 32);

    v2 += v3;
    v3 = rotl64(v3, 16);
    v3 ^= v2;

    v0 += v3;
    v3 = rotl64(v3, 21);
    v3 ^= v0;

    v2 += v1;
    v1 = rotl64(v1, 17);
    v1 ^= v2;
    v2 = rotl64(v2, 32);
}

/// Read a 64-bit little-endian word from a possibly-unaligned pointer.
inline uint64_t load_le64(const uint8_t* p) noexcept {
    uint64_t v;
    std::memcpy(&v, p, 8);
    // The protocol stores integers in little-endian byte order
    // and all supported platforms are little-endian (x86-64, ARM64).
    // On a hypothetical big-endian target a byte-swap would be
    // required here.
    return v;
}

}  // namespace

// ===================================================================
// Construction
// ===================================================================

SipHash::SipHash(uint64_t k0, uint64_t k1)
    : v0_(0x736f6d6570736575ULL ^ k0)
    , v1_(0x646f72616e646f6dULL ^ k1)
    , v2_(0x6c7967656e657261ULL ^ k0)
    , v3_(0x7465646279746573ULL ^ k1) {}

// ===================================================================
// Compression
// ===================================================================

void SipHash::compress(uint64_t m) {
    v3_ ^= m;
    // SipHash-2-4: two rounds per message block.
    sip_round(v0_, v1_, v2_, v3_);
    sip_round(v0_, v1_, v2_, v3_);
    v0_ ^= m;
}

// ===================================================================
// Incremental write
// ===================================================================

SipHash& SipHash::write(std::span<const uint8_t> data) {
    const uint8_t* ptr = data.data();
    size_t remaining = data.size();

    count_ += remaining;

    // Number of bytes already accumulated in tmp_.
    size_t buf_bytes = static_cast<size_t>(
        (count_ - remaining) & 7);

    if (buf_bytes > 0) {
        // Fill the partial word first.
        size_t fill = 8 - buf_bytes;
        if (remaining < fill) {
            // Not enough to complete a word -- just accumulate.
            for (size_t i = 0; i < remaining; ++i) {
                tmp_ |= static_cast<uint64_t>(ptr[i])
                         << (8 * (buf_bytes + i));
            }
            return *this;
        }
        // Complete the partial word and compress it.
        for (size_t i = 0; i < fill; ++i) {
            tmp_ |= static_cast<uint64_t>(ptr[i])
                     << (8 * (buf_bytes + i));
        }
        compress(tmp_);
        tmp_ = 0;
        ptr += fill;
        remaining -= fill;
    }

    // Process full 8-byte blocks.
    while (remaining >= 8) {
        compress(load_le64(ptr));
        ptr += 8;
        remaining -= 8;
    }

    // Accumulate any trailing bytes into tmp_.
    tmp_ = 0;
    for (size_t i = 0; i < remaining; ++i) {
        tmp_ |= static_cast<uint64_t>(ptr[i]) << (8 * i);
    }

    return *this;
}

SipHash& SipHash::write_u64(uint64_t val) {
    uint8_t buf[8];
    std::memcpy(buf, &val, 8);
    return write(std::span<const uint8_t>(buf, 8));
}

SipHash& SipHash::write_u32(uint32_t val) {
    uint8_t buf[4];
    std::memcpy(buf, &val, 4);
    return write(std::span<const uint8_t>(buf, 4));
}

// ===================================================================
// Finalization
// ===================================================================

uint64_t SipHash::finalize() {
    // Pad the last block: the final byte encodes (count mod 256).
    uint64_t last = tmp_;
    last |= static_cast<uint64_t>(count_ & 0xFF) << 56;
    compress(last);

    // SipHash-2-4: four finalisation rounds with v2 XOR 0xFF.
    v2_ ^= 0xFFULL;
    sip_round(v0_, v1_, v2_, v3_);
    sip_round(v0_, v1_, v2_, v3_);
    sip_round(v0_, v1_, v2_, v3_);
    sip_round(v0_, v1_, v2_, v3_);

    return v0_ ^ v1_ ^ v2_ ^ v3_;
}

// ===================================================================
// One-shot convenience functions
// ===================================================================

uint64_t siphash(uint64_t k0, uint64_t k1,
                 const core::uint256& val) {
    return siphash(k0, k1,
        std::span<const uint8_t>(val.data(), val.size()));
}

uint64_t siphash(uint64_t k0, uint64_t k1,
                 std::span<const uint8_t> data) {
    SipHash hasher(k0, k1);
    hasher.write(data);
    return hasher.finalize();
}

}  // namespace crypto
