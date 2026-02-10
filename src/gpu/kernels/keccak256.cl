// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// keccak256.cl -- NIST SHA3-256 for OpenCL
// =========================================================================
//
// This file implements the NIST SHA3-256 hash function (FIPS 202) on the
// GPU.  It is optimized for fixed-size inputs used by the FTC miner.
//
// CRITICAL: This is NIST SHA3-256, NOT Ethereum Keccak-256.
//   - SHA3-256 padding byte:    0x06
//   - Ethereum Keccak padding:  0x01
//   The Keccak-f[1600] permutation is identical; only the padding differs.
//
// SHA3-256 parameters:
//   - State: 1600 bits = 200 bytes = 25 ulong lanes (5x5 matrix)
//   - Rate:  1088 bits = 136 bytes = 17 ulong lanes
//   - Capacity: 512 bits = 64 bytes = 8 ulong lanes
//   - Output: 256 bits = 32 bytes = 4 ulong lanes
//
// For a 36-byte message (< 136 byte rate):
//   1. Initialize 25-lane state to zero
//   2. XOR message bytes into the first lanes (rate portion)
//   3. Apply SHA3 padding:
//      - Byte 36: XOR with 0x06 (SHA3 domain separator)
//      - Byte 135 (last byte of rate): XOR with 0x80
//   4. Apply Keccak-f[1600] permutation (24 rounds)
//   5. Read first 32 bytes (4 lanes) as output
//   6. Read output bytes
//
// All values are little-endian within each 64-bit lane.
// =========================================================================

#ifndef KECCAK256_CL
#define KECCAK256_CL

// -------------------------------------------------------------------------
// Keccak-f[1600] round constants (24 rounds)
//
// These are the iota step constants, derived from a linear feedback shift
// register.  Each constant is XOR'd into lane (0,0) at the end of the
// corresponding round.
// -------------------------------------------------------------------------

__constant ulong RC[24] = {
    0x0000000000000001UL,
    0x0000000000008082UL,
    0x800000000000808AUL,
    0x8000000080008000UL,
    0x000000000000808BUL,
    0x0000000080000001UL,
    0x8000000080008081UL,
    0x8000000000008009UL,
    0x000000000000008AUL,
    0x0000000000000088UL,
    0x0000000080008009UL,
    0x000000008000000AUL,
    0x000000008000808BUL,
    0x800000000000008BUL,
    0x8000000000008089UL,
    0x8000000000008003UL,
    0x8000000000008002UL,
    0x8000000000000080UL,
    0x000000000000800AUL,
    0x800000008000000AUL,
    0x8000000080008081UL,
    0x8000000000008080UL,
    0x0000000080000001UL,
    0x8000000080008008UL
};

// -------------------------------------------------------------------------
// Rotation offsets for the rho step
//
// Indexed as [x + 5*y] for the 5x5 state matrix.
// These are the number of bit positions each lane is rotated left by.
//
// Lane (0,0) has offset 0 (not rotated).
// The offsets for the remaining 24 lanes are derived from the specification:
//   - Start at (x,y) = (1,0)
//   - Iterate: (x,y) = (y, 2x+3y mod 5) for t = 0..23
//   - Rotation offset = (t+1)(t+2)/2 mod 64
// -------------------------------------------------------------------------

// Rho offsets indexed by linear index [x + 5*y]:
//
//   (x,y):  (0,0)=0  (1,0)=1  (2,0)=62 (3,0)=28 (4,0)=27
//           (0,1)=36 (1,1)=44 (2,1)=6  (3,1)=55 (4,1)=20
//           (0,2)=3  (1,2)=10 (2,2)=43 (3,2)=25 (4,2)=39
//           (0,3)=41 (1,3)=45 (2,3)=15 (3,3)=21 (4,3)=8
//           (0,4)=18 (1,4)=2  (2,4)=61 (3,4)=56 (4,4)=14

// -------------------------------------------------------------------------
// Rotate-left helper for 64-bit values
// -------------------------------------------------------------------------

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// -------------------------------------------------------------------------
// Keccak-f[1600] permutation -- 24 rounds
//
// The state is 25 ulong lanes arranged as a 5x5 matrix A[x][y],
// stored linearly as st[x + 5*y].
//
// Each round applies 5 steps: theta, rho, pi, chi, iota.
// -------------------------------------------------------------------------

// __attribute__((noinline)): NVIDIA's OpenCL compiler silently inlines all
// device functions and then aggressively optimizes the combined code, which
// on Ada Lovelace / Blackwell GPUs eliminates the keccak loop body entirely.
// Preventing inlining forces the compiler to treat st[] as an opaque pointer,
// preserving all writes while still optimizing the function body itself.
static void __attribute__((noinline)) keccak_f1600(ulong st[25])
{
    // Temporary array for rho+pi step -- declared outside the loop
    // to reduce register/stack pressure (avoids 24 copies if unrolled).
    ulong tmp[25];

    for (int round = 0; round < 24; round++) {
        ulong t, bc0, bc1, bc2, bc3, bc4;

        // ---- Theta step ----
        // Compute column parities.
        bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        // XOR each column with (left_neighbor ^ rot(right_neighbor, 1)).
        t = bc4 ^ ROL64(bc1, 1); st[0]  ^= t; st[5]  ^= t; st[10] ^= t; st[15] ^= t; st[20] ^= t;
        t = bc0 ^ ROL64(bc2, 1); st[1]  ^= t; st[6]  ^= t; st[11] ^= t; st[16] ^= t; st[21] ^= t;
        t = bc1 ^ ROL64(bc3, 1); st[2]  ^= t; st[7]  ^= t; st[12] ^= t; st[17] ^= t; st[22] ^= t;
        t = bc2 ^ ROL64(bc4, 1); st[3]  ^= t; st[8]  ^= t; st[13] ^= t; st[18] ^= t; st[23] ^= t;
        t = bc3 ^ ROL64(bc0, 1); st[4]  ^= t; st[9]  ^= t; st[14] ^= t; st[19] ^= t; st[24] ^= t;

        // ---- Rho + Pi steps (combined) ----
        // Rho rotates each lane, Pi moves lanes to new positions.
        // Combined: tmp[pi(x,y)] = rot(st[x+5y], rho_offset[x+5y])
        // Pi mapping: A'[y][2x+3y mod 5] = A[x][y]
        //   i.e., new position = y + 5*(2x+3y mod 5)
        //
        // We compute this in a single pass using a temporary array.
        {
            // (x=0,y=0): new_pos = 0 + 5*(0) = 0,  rho=0
            tmp[0]  = st[0];  // ROL64(st[0], 0) = st[0]

            // (x=1,y=0): new_pos = 0 + 5*(2*1+0 mod 5) = 0+5*2 = 10,  rho=1
            tmp[10] = ROL64(st[1], 1);

            // (x=2,y=0): new_pos = 0 + 5*(2*2+0 mod 5) = 0+5*4 = 20,  rho=62
            tmp[20] = ROL64(st[2], 62);

            // (x=3,y=0): new_pos = 0 + 5*(2*3+0 mod 5) = 0+5*1 = 5,  rho=28
            tmp[5]  = ROL64(st[3], 28);

            // (x=4,y=0): new_pos = 0 + 5*(2*4+0 mod 5) = 0+5*3 = 15,  rho=27
            tmp[15] = ROL64(st[4], 27);

            // (x=0,y=1): new_pos = 1 + 5*(0+3 mod 5) = 1+5*3 = 16,  rho=36
            tmp[16] = ROL64(st[5], 36);

            // (x=1,y=1): new_pos = 1 + 5*(2+3 mod 5) = 1+5*0 = 1,  rho=44
            tmp[1]  = ROL64(st[6], 44);

            // (x=2,y=1): new_pos = 1 + 5*(4+3 mod 5) = 1+5*2 = 11,  rho=6
            tmp[11] = ROL64(st[7], 6);

            // (x=3,y=1): new_pos = 1 + 5*(6+3 mod 5) = 1+5*4 = 21,  rho=55
            tmp[21] = ROL64(st[8], 55);

            // (x=4,y=1): new_pos = 1 + 5*(8+3 mod 5) = 1+5*1 = 6,  rho=20
            tmp[6]  = ROL64(st[9], 20);

            // (x=0,y=2): new_pos = 2 + 5*(0+6 mod 5) = 2+5*1 = 7,  rho=3
            tmp[7]  = ROL64(st[10], 3);

            // (x=1,y=2): new_pos = 2 + 5*(2+6 mod 5) = 2+5*3 = 17,  rho=10
            tmp[17] = ROL64(st[11], 10);

            // (x=2,y=2): new_pos = 2 + 5*(4+6 mod 5) = 2+5*0 = 2,  rho=43
            tmp[2]  = ROL64(st[12], 43);

            // (x=3,y=2): new_pos = 2 + 5*(6+6 mod 5) = 2+5*2 = 12,  rho=25
            tmp[12] = ROL64(st[13], 25);

            // (x=4,y=2): new_pos = 2 + 5*(8+6 mod 5) = 2+5*4 = 22,  rho=39
            tmp[22] = ROL64(st[14], 39);

            // (x=0,y=3): new_pos = 3 + 5*(0+9 mod 5) = 3+5*4 = 23,  rho=41
            tmp[23] = ROL64(st[15], 41);

            // (x=1,y=3): new_pos = 3 + 5*(2+9 mod 5) = 3+5*1 = 8,  rho=45
            tmp[8]  = ROL64(st[16], 45);

            // (x=2,y=3): new_pos = 3 + 5*(4+9 mod 5) = 3+5*3 = 18,  rho=15
            tmp[18] = ROL64(st[17], 15);

            // (x=3,y=3): new_pos = 3 + 5*(6+9 mod 5) = 3+5*0 = 3,  rho=21
            tmp[3]  = ROL64(st[18], 21);

            // (x=4,y=3): new_pos = 3 + 5*(8+9 mod 5) = 3+5*2 = 13,  rho=8
            tmp[13] = ROL64(st[19], 8);

            // (x=0,y=4): new_pos = 4 + 5*(0+12 mod 5) = 4+5*2 = 14,  rho=18
            tmp[14] = ROL64(st[20], 18);

            // (x=1,y=4): new_pos = 4 + 5*(2+12 mod 5) = 4+5*4 = 24,  rho=2
            tmp[24] = ROL64(st[21], 2);

            // (x=2,y=4): new_pos = 4 + 5*(4+12 mod 5) = 4+5*1 = 9,  rho=61
            tmp[9]  = ROL64(st[22], 61);

            // (x=3,y=4): new_pos = 4 + 5*(6+12 mod 5) = 4+5*3 = 19,  rho=56
            tmp[19] = ROL64(st[23], 56);

            // (x=4,y=4): new_pos = 4 + 5*(8+12 mod 5) = 4+5*0 = 4,  rho=14
            tmp[4]  = ROL64(st[24], 14);

            // Copy back for chi step.
            for (int i = 0; i < 25; i++) {
                st[i] = tmp[i];
            }
        }

        // ---- Chi step ----
        // For each row y: A'[x][y] = A[x][y] ^ (~A[x+1][y] & A[x+2][y])
        for (int y = 0; y < 5; y++) {
            int base = y * 5;
            ulong a0 = st[base + 0];
            ulong a1 = st[base + 1];
            ulong a2 = st[base + 2];
            ulong a3 = st[base + 3];
            ulong a4 = st[base + 4];

            st[base + 0] = a0 ^ (~a1 & a2);
            st[base + 1] = a1 ^ (~a2 & a3);
            st[base + 2] = a2 ^ (~a3 & a4);
            st[base + 3] = a3 ^ (~a4 & a0);
            st[base + 4] = a4 ^ (~a0 & a1);
        }

        // ---- Iota step ----
        // XOR round constant into lane (0,0).
        st[0] ^= RC[round];
    }
}

// -------------------------------------------------------------------------
// SHA3-256 for exactly 36-byte input
//
// This function computes NIST SHA3-256 of a 36-byte message and returns
// the first 25 bytes of the 32-byte digest.
//
// Parameters:
//   input32 -- pointer to the 32-byte hash input (constant across
//              all work items; this is keccak256(serialized_header))
//   index   -- the 4-byte index (appended as LE32)
//   out25   -- output buffer receiving 25 bytes of digest
//
// The 36-byte preimage is:  input32[0..31] || le32(index)
//
// State layout after absorbing (all in little-endian lane order):
//
//   Lane 0 (bytes  0.. 7): input32[ 0.. 7]
//   Lane 1 (bytes  8..15): input32[ 8..15]
//   Lane 2 (bytes 16..23): input32[16..23]
//   Lane 3 (bytes 24..31): input32[24..31]
//   Lane 4 (bytes 32..39): le32(index) [4 bytes] || 0x06 [SHA3 pad] ||
//                           0x00 0x00 0x00
//   Lanes 5..15: 0
//   Lane 16 (bytes 128..135): 0x80 at byte 135 (MSB of lane 16)
//   Lanes 17..24: 0  (capacity portion, not part of rate)
//
// Byte 36 = 0x06 is the SHA3 domain separator (NOT 0x01 for raw Keccak).
// Byte 135 = 0x80 is the padding terminator (last byte of the rate).
// -------------------------------------------------------------------------

inline void sha3_256_36bytes(__global const uchar* input32,
                             uint index,
                             uchar out25[25])
{
    // Initialize state to zero.
    ulong st[25];
    for (int i = 0; i < 25; i++) {
        st[i] = 0;
    }

    // Absorb the 32-byte constant input into lanes 0..3.
    // Each lane is 8 bytes, little-endian.
    st[0] = (ulong)input32[0]
          | ((ulong)input32[1]  << 8)
          | ((ulong)input32[2]  << 16)
          | ((ulong)input32[3]  << 24)
          | ((ulong)input32[4]  << 32)
          | ((ulong)input32[5]  << 40)
          | ((ulong)input32[6]  << 48)
          | ((ulong)input32[7]  << 56);

    st[1] = (ulong)input32[8]
          | ((ulong)input32[9]  << 8)
          | ((ulong)input32[10] << 16)
          | ((ulong)input32[11] << 24)
          | ((ulong)input32[12] << 32)
          | ((ulong)input32[13] << 40)
          | ((ulong)input32[14] << 48)
          | ((ulong)input32[15] << 56);

    st[2] = (ulong)input32[16]
          | ((ulong)input32[17] << 8)
          | ((ulong)input32[18] << 16)
          | ((ulong)input32[19] << 24)
          | ((ulong)input32[20] << 32)
          | ((ulong)input32[21] << 40)
          | ((ulong)input32[22] << 48)
          | ((ulong)input32[23] << 56);

    st[3] = (ulong)input32[24]
          | ((ulong)input32[25] << 8)
          | ((ulong)input32[26] << 16)
          | ((ulong)input32[27] << 24)
          | ((ulong)input32[28] << 32)
          | ((ulong)input32[29] << 40)
          | ((ulong)input32[30] << 48)
          | ((ulong)input32[31] << 56);

    // Lane 4: bytes 32..39 of the rate.
    // Bytes 32..35 = le32(index), byte 36 = 0x06 (SHA3 pad), bytes 37..39 = 0.
    //
    // In little-endian lane layout:
    //   byte 32 = index & 0xFF           -> bits 0..7
    //   byte 33 = (index >> 8) & 0xFF    -> bits 8..15
    //   byte 34 = (index >> 16) & 0xFF   -> bits 16..23
    //   byte 35 = (index >> 24) & 0xFF   -> bits 24..31
    //   byte 36 = 0x06                   -> bits 32..39
    //   bytes 37..39 = 0x00              -> bits 40..63
    st[4] = (ulong)index | ((ulong)0x06 << 32);

    // Lanes 5..15 remain zero (no more message bytes).

    // Lane 16: byte 135 (the last byte of the 136-byte rate) gets 0x80.
    // Byte 135 is the last byte of lane 16 (bytes 128..135).
    // In little-endian: byte 135 is the most significant byte of lane 16.
    st[16] = 0x8000000000000000UL;

    // Lanes 17..24 remain zero (capacity portion).

    // Apply Keccak-f[1600] permutation.
    keccak_f1600(st);

    // Extract the first 25 bytes of output (from lanes 0..3).
    // Lane 0 = output bytes 0..7, Lane 1 = bytes 8..15,
    // Lane 2 = bytes 16..23, Lane 3 = bytes 24..31.
    // We need bytes 0..24 (25 bytes).

    // Lanes 0..2: full 24 bytes.
    for (int i = 0; i < 3; i++) {
        ulong lane = st[i];
        out25[i * 8 + 0] = (uchar)(lane);
        out25[i * 8 + 1] = (uchar)(lane >> 8);
        out25[i * 8 + 2] = (uchar)(lane >> 16);
        out25[i * 8 + 3] = (uchar)(lane >> 24);
        out25[i * 8 + 4] = (uchar)(lane >> 32);
        out25[i * 8 + 5] = (uchar)(lane >> 40);
        out25[i * 8 + 6] = (uchar)(lane >> 48);
        out25[i * 8 + 7] = (uchar)(lane >> 56);
    }

    // Lane 3: only the first byte (byte 24).
    out25[24] = (uchar)(st[3]);
}

// -------------------------------------------------------------------------
// Variant that reads input from private memory instead of global
// (useful if the caller has already cached the 32-byte input locally)
// -------------------------------------------------------------------------

inline void sha3_256_36bytes_priv(const uchar input32[32],
                                  uint index,
                                  uchar out25[25])
{
    ulong st[25];
    for (int i = 0; i < 25; i++) {
        st[i] = 0;
    }

    st[0] = (ulong)input32[0]
          | ((ulong)input32[1]  << 8)
          | ((ulong)input32[2]  << 16)
          | ((ulong)input32[3]  << 24)
          | ((ulong)input32[4]  << 32)
          | ((ulong)input32[5]  << 40)
          | ((ulong)input32[6]  << 48)
          | ((ulong)input32[7]  << 56);

    st[1] = (ulong)input32[8]
          | ((ulong)input32[9]  << 8)
          | ((ulong)input32[10] << 16)
          | ((ulong)input32[11] << 24)
          | ((ulong)input32[12] << 32)
          | ((ulong)input32[13] << 40)
          | ((ulong)input32[14] << 48)
          | ((ulong)input32[15] << 56);

    st[2] = (ulong)input32[16]
          | ((ulong)input32[17] << 8)
          | ((ulong)input32[18] << 16)
          | ((ulong)input32[19] << 24)
          | ((ulong)input32[20] << 32)
          | ((ulong)input32[21] << 40)
          | ((ulong)input32[22] << 48)
          | ((ulong)input32[23] << 56);

    st[3] = (ulong)input32[24]
          | ((ulong)input32[25] << 8)
          | ((ulong)input32[26] << 16)
          | ((ulong)input32[27] << 24)
          | ((ulong)input32[28] << 32)
          | ((ulong)input32[29] << 40)
          | ((ulong)input32[30] << 48)
          | ((ulong)input32[31] << 56);

    st[4] = (ulong)index | ((ulong)0x06 << 32);
    st[16] = 0x8000000000000000UL;

    keccak_f1600(st);

    for (int i = 0; i < 3; i++) {
        ulong lane = st[i];
        out25[i * 8 + 0] = (uchar)(lane);
        out25[i * 8 + 1] = (uchar)(lane >> 8);
        out25[i * 8 + 2] = (uchar)(lane >> 16);
        out25[i * 8 + 3] = (uchar)(lane >> 24);
        out25[i * 8 + 4] = (uchar)(lane >> 32);
        out25[i * 8 + 5] = (uchar)(lane >> 40);
        out25[i * 8 + 6] = (uchar)(lane >> 48);
        out25[i * 8 + 7] = (uchar)(lane >> 56);
    }

    out25[24] = (uchar)(st[3]);
}

#endif // KECCAK256_CL
