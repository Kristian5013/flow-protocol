// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// keccak_mine.cl -- GPU Keccak256d nonce-grinding miner kernel
// =========================================================================
//
// FTC proof-of-work: keccak256d(header_80bytes) <= target
//   where keccak256d(x) = SHA3-256(SHA3-256(x))
//
// The 80-byte block header layout:
//   bytes  0- 3: version       (int32_t LE)
//   bytes  4-35: prev_hash     (32 bytes)
//   bytes 36-67: merkle_root   (32 bytes)
//   bytes 68-71: timestamp     (uint32_t LE)
//   bytes 72-75: bits          (uint32_t LE)
//   bytes 76-79: nonce         (uint32_t LE)  <-- varies per work item
//
// Optimization: the first 76 bytes are constant across all nonces.
// We precompute the Keccak sponge lanes 0-8 on the host and upload
// them as constants.  Lane 9 = bits(LE32) | (nonce << 32).
// Only the upper 32 bits of lane 9 change per work item.
//
// Each work item:
//   1. Build state from precomputed lanes + nonce
//   2. Apply SHA3-256 padding + Keccak-f[1600]  (first hash)
//   3. Feed 32-byte result into second SHA3-256  (second hash)
//   4. Compare result against target (256-bit LE unsigned)
//   5. If hash <= target, atomically store winning nonce
// =========================================================================

// Note: keccak256.cl (providing keccak_f1600) is concatenated before
// this file by the host code.  No #include needed.

// -------------------------------------------------------------------------
// Compare hash <= target as 256-bit unsigned integers.
//
// Both hash and target are represented as 4 ulong lanes in the same
// format as SHA3-256 output (little-endian lane order):
//   lane[0] = least significant 64 bits  (bytes 0-7)
//   lane[3] = most significant 64 bits   (bytes 24-31)
//
// Within each lane, bytes are in LE order, matching the uint256 storage.
// The uint256 comparison goes byte[31] (MSB) down to byte[0] (LSB),
// which is equivalent to comparing the lanes as regular 64-bit unsigned
// integers in reverse order (lane 3 first, then 2, 1, 0).
// No byte swapping needed -- LE lane comparison == LE uint256 comparison.
// -------------------------------------------------------------------------
static inline bool hash_le_target(ulong h0, ulong h1, ulong h2, ulong h3,
                           ulong t0, ulong t1, ulong t2, ulong t3)
{
    // Compare most significant lane first (lane 3 = bytes 24-31)
    if (h3 < t3) return true;
    if (h3 > t3) return false;

    if (h2 < t2) return true;
    if (h2 > t2) return false;

    if (h1 < t1) return true;
    if (h1 > t1) return false;

    if (h0 < t0) return true;
    if (h0 > t0) return false;

    return true;  // equal => hash <= target
}

// -------------------------------------------------------------------------
// Main mining kernel
//
// Parameters:
//   header_lanes  -- 10 ulong values: precomputed lanes 0-9 from the
//                    80-byte header with nonce=0.  Lane 9 low 32 bits
//                    contain the 'bits' field; high 32 bits are zero.
//   base_nonce    -- starting nonce for this batch
//   target_lanes  -- 4 ulong values: the target as uint256 lanes
//   result_nonces -- output array for winning nonces (max 8)
//   result_count  -- atomic counter for number of solutions found
// -------------------------------------------------------------------------

__kernel void keccak256d_mine(
    __global const ulong* header_lanes,
    uint base_nonce,
    __global const ulong* target_lanes,
    __global uint* result_nonces,
    __global uint* result_count)
{
    uint nonce = base_nonce + (uint)get_global_id(0);

    // ---- First SHA3-256: hash the 80-byte header ----
    ulong st[25];
    for (int i = 0; i < 25; i++) st[i] = 0;

    // Absorb precomputed lanes 0-8 (bytes 0-71, constant across nonces)
    st[0] = header_lanes[0];
    st[1] = header_lanes[1];
    st[2] = header_lanes[2];
    st[3] = header_lanes[3];
    st[4] = header_lanes[4];
    st[5] = header_lanes[5];
    st[6] = header_lanes[6];
    st[7] = header_lanes[7];
    st[8] = header_lanes[8];

    // Lane 9 (bytes 72-79): bits(LE32) in low 32, nonce(LE32) in high 32
    st[9] = (header_lanes[9] & 0xFFFFFFFFUL) | ((ulong)nonce << 32);

    // SHA3-256 padding for 80-byte message:
    //   byte 80 = 0x06 (SHA3 domain separator)  => lane 10, low byte
    //   byte 135 = 0x80 (pad terminator)         => lane 16, high byte
    st[10] = 0x06UL;
    st[16] = 0x8000000000000000UL;

    keccak_f1600(st);

    // Save first-hash output (32 bytes = 4 lanes)
    ulong h0 = st[0], h1 = st[1], h2 = st[2], h3 = st[3];

    // ---- Second SHA3-256: hash the 32-byte digest ----
    for (int i = 0; i < 25; i++) st[i] = 0;

    st[0] = h0;
    st[1] = h1;
    st[2] = h2;
    st[3] = h3;

    // SHA3-256 padding for 32-byte message:
    //   byte 32 = 0x06 => lane 4, low byte
    //   byte 135 = 0x80 => lane 16, high byte
    st[4] = 0x06UL;
    st[16] = 0x8000000000000000UL;

    keccak_f1600(st);

    // ---- Compare hash <= target ----
    ulong t0 = target_lanes[0];
    ulong t1 = target_lanes[1];
    ulong t2 = target_lanes[2];
    ulong t3 = target_lanes[3];

    if (hash_le_target(st[0], st[1], st[2], st[3], t0, t1, t2, t3)) {
        uint idx = atomic_inc(result_count);
        if (idx < 8) {
            result_nonces[idx] = nonce;
        }
    }
}
