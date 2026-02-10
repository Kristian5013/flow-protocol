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
//
// Implementation uses 25 individual scalar ulong variables (s00..s44)
// to prevent NVIDIA dead-store elimination on Blackwell/Ada GPUs.
// See keccak256.cl for the KECCAK_F1600 macro.
// =========================================================================

// Note: keccak256.cl (providing KECCAK_ROUND / KECCAK_F1600 macros)
// is concatenated before this file by the host code.  No #include needed.

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
//
// Variable naming: sXY where state index = X + 5*Y  (X=column, Y=row)
//   s00=st[0]  s10=st[1]  s20=st[2]  s30=st[3]  s40=st[4]
//   s01=st[5]  s11=st[6]  s21=st[7]  s31=st[8]  s41=st[9]
//   s02=st[10] s12=st[11] s22=st[12] s32=st[13] s42=st[14]
//   s03=st[15] s13=st[16] s23=st[17] s33=st[18] s43=st[19]
//   s04=st[20] s14=st[21] s24=st[22] s34=st[23] s44=st[24]
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
    // Initialize 25 scalar state variables to zero
    ulong s00 = 0, s10 = 0, s20 = 0, s30 = 0, s40 = 0;
    ulong s01 = 0, s11 = 0, s21 = 0, s31 = 0, s41 = 0;
    ulong s02 = 0, s12 = 0, s22 = 0, s32 = 0, s42 = 0;
    ulong s03 = 0, s13 = 0, s23 = 0, s33 = 0, s43 = 0;
    ulong s04 = 0, s14 = 0, s24 = 0, s34 = 0, s44 = 0;

    // Absorb precomputed lanes 0-8 (bytes 0-71, constant across nonces)
    // st[0]-st[4] = s00, s10, s20, s30, s40
    s00 = header_lanes[0];
    s10 = header_lanes[1];
    s20 = header_lanes[2];
    s30 = header_lanes[3];
    s40 = header_lanes[4];
    // st[5]-st[8] = s01, s11, s21, s31
    s01 = header_lanes[5];
    s11 = header_lanes[6];
    s21 = header_lanes[7];
    s31 = header_lanes[8];

    // Lane 9 (st[9] = s41): bits(LE32) in low 32, nonce(LE32) in high 32
    s41 = (header_lanes[9] & 0xFFFFFFFFUL) | ((ulong)nonce << 32);

    // SHA3-256 padding for 80-byte message:
    //   byte 80 = 0x06 (SHA3 domain separator)  => st[10] = s02, low byte
    //   byte 135 = 0x80 (pad terminator)         => st[16] = s13, high byte
    s02 = 0x06UL;
    s13 = 0x8000000000000000UL;

    // Apply Keccak-f[1600] (24 rounds, fully unrolled)
    KECCAK_F1600();

    // Save first-hash output (32 bytes = 4 lanes = st[0]-st[3] = s00,s10,s20,s30)
    ulong h0 = s00, h1 = s10, h2 = s20, h3 = s30;

    // ---- Second SHA3-256: hash the 32-byte digest ----
    // Re-initialize all 25 state variables to zero
    s00 = 0; s10 = 0; s20 = 0; s30 = 0; s40 = 0;
    s01 = 0; s11 = 0; s21 = 0; s31 = 0; s41 = 0;
    s02 = 0; s12 = 0; s22 = 0; s32 = 0; s42 = 0;
    s03 = 0; s13 = 0; s23 = 0; s33 = 0; s43 = 0;
    s04 = 0; s14 = 0; s24 = 0; s34 = 0; s44 = 0;

    // Absorb first hash into st[0]-st[3] = s00, s10, s20, s30
    s00 = h0;
    s10 = h1;
    s20 = h2;
    s30 = h3;

    // SHA3-256 padding for 32-byte message:
    //   byte 32 = 0x06 => st[4] = s40, low byte
    //   byte 135 = 0x80 => st[16] = s13, high byte
    s40 = 0x06UL;
    s13 = 0x8000000000000000UL;

    // Apply Keccak-f[1600] (24 rounds, fully unrolled)
    KECCAK_F1600();

    // ---- Compare hash <= target ----
    // Hash output lanes: st[0]-st[3] = s00, s10, s20, s30
    ulong t0 = target_lanes[0];
    ulong t1 = target_lanes[1];
    ulong t2 = target_lanes[2];
    ulong t3 = target_lanes[3];

    if (hash_le_target(s00, s10, s20, s30, t0, t1, t2, t3)) {
        uint idx = atomic_inc(result_count);
        if (idx < 8) {
            result_nonces[idx] = nonce;
        }
    }
}
