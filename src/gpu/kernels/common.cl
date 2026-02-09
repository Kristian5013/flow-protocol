// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// common.cl -- Equihash (200,9) GPU miner: shared constants and types
// =========================================================================
//
// This file defines all constants, parameters, and shared data types used
// across the Equihash OpenCL kernels.  It is included by every other .cl
// file via #include "common.cl".
//
// Equihash (n=200, k=9) parameters:
//   - 200-bit hash output (25 bytes)
//   - 9 Wagner collision rounds
//   - 20 collision bits per round  (n/(k+1) = 200/10 = 20)
//   - 21-bit indices               (n/(k+1) + 1 = 21)
//   - 2^21 = 2,097,152 initial hashes
//   - 512 indices per solution     (2^k = 2^9 = 512)
//   - 1344-byte packed solution    ((512 * 21 + 7) / 8 = 1344)
//
// Memory layout:
//   Slots are stored in bucket-major order across 10 table regions
//   (one for the initial hashes, one per collision round).  Each table
//   region is indexed as: base + bucket * MAX_SLOTS + slot_index.
//   Bucket counters are stored separately per region.
//
// =========================================================================

#ifndef COMMON_CL
#define COMMON_CL

// -------------------------------------------------------------------------
// Equihash (n, k) fundamental parameters
// -------------------------------------------------------------------------

#define EQ_N                200         // collision bit length
#define EQ_K                9           // number of Wagner rounds

// -------------------------------------------------------------------------
// Derived parameters
// -------------------------------------------------------------------------

#define COLLISION_BITS      20          // n / (k+1) = 200 / 10
#define INDEX_BITS          21          // n / (k+1) + 1 = 21
#define NUM_INDICES         (1u << 21)  // 2^21 = 2,097,152
#define HASH_LEN            25          // ceil(n/8) = 25 bytes
#define SOLUTION_SIZE       1344        // (512 * 21 + 7) / 8
#define NUM_SOLUTIONS_INDICES 512       // 2^k = 2^9

// -------------------------------------------------------------------------
// Bucket parameters
// -------------------------------------------------------------------------
//
// We use the top BUCKET_BITS (12) of each 20-bit collision window as the
// bucket key, leaving 8 "intra-bucket" bits for matching within a bucket.
// This yields 4096 buckets.
//
// With 2^21 initial hashes distributed across 4096 buckets, the average
// occupancy is 512.  MAX_SLOTS = 684 provides ~33% headroom for variance.
// -------------------------------------------------------------------------

#define BUCKET_BITS         12
#define INTRA_BITS          8           // COLLISION_BITS - BUCKET_BITS
#define NUM_BUCKETS         (1u << BUCKET_BITS)  // 4096
#define MAX_SLOTS           684

// -------------------------------------------------------------------------
// Slot format (32 bytes each)
// -------------------------------------------------------------------------
//
// For the initial table (round 0, written by equihash_init):
//   bytes [0..24]  : 25-byte hash H(i) = SHA3-256(input || le32(i))[0:25]
//   bytes [25..27] : zero padding
//   bytes [28..31] : original index i (uint32, little-endian)
//
// For collision tables (rounds 1..9, written by equihash_round):
//   bytes [0..23]  : 24 bytes of XOR'd hash data
//   bytes [24..27] : ref0 (uint32) -- left parent slot (table-relative)
//   bytes [28..31] : ref1 (uint32) -- right parent slot (table-relative)
//
// Note: We store only 24 of the 25 hash bytes in collision tables.
// This loses 8 bits (bits 192-199), which means we may produce rare
// false positives in the final round.  These are caught cheaply by
// CPU verification.
// -------------------------------------------------------------------------

#define SLOT_SIZE           32
#define TABLE_SIZE          ((uint)NUM_BUCKETS * MAX_SLOTS)

// -------------------------------------------------------------------------
// Solution output limits
// -------------------------------------------------------------------------

#define MAX_SOLUTIONS       8

// -------------------------------------------------------------------------
// Useful constants
// -------------------------------------------------------------------------

// Total number of table regions: init (0) + 9 collision rounds (1..9)
#define NUM_TABLES          10

// -------------------------------------------------------------------------
// Helper: read a little-endian uint32 from a byte pointer
// -------------------------------------------------------------------------

inline uint read_le32(const __global uchar* p) {
    return (uint)p[0]
         | ((uint)p[1] << 8)
         | ((uint)p[2] << 16)
         | ((uint)p[3] << 24);
}

inline uint read_le32_local(const __local uchar* p) {
    return (uint)p[0]
         | ((uint)p[1] << 8)
         | ((uint)p[2] << 16)
         | ((uint)p[3] << 24);
}

inline uint read_le32_priv(const uchar* p) {
    return (uint)p[0]
         | ((uint)p[1] << 8)
         | ((uint)p[2] << 16)
         | ((uint)p[3] << 24);
}

// -------------------------------------------------------------------------
// Helper: write a little-endian uint32 to a byte pointer
// -------------------------------------------------------------------------

inline void write_le32(__global uchar* p, uint val) {
    p[0] = (uchar)(val);
    p[1] = (uchar)(val >> 8);
    p[2] = (uchar)(val >> 16);
    p[3] = (uchar)(val >> 24);
}

inline void write_le32_priv(uchar* p, uint val) {
    p[0] = (uchar)(val);
    p[1] = (uchar)(val >> 8);
    p[2] = (uchar)(val >> 16);
    p[3] = (uchar)(val >> 24);
}

// -------------------------------------------------------------------------
// Helper: extract an arbitrary-width bit field from a byte array
//
// Reads up to 32 bits starting at bit position `bit_offset` from the
// byte array `data` of length `data_len`.  The byte array is treated as
// a big-endian bit stream (bit 0 is the MSB of byte 0).
// -------------------------------------------------------------------------

inline uint extract_bits(const uchar* data, uint data_len,
                         uint bit_offset, uint num_bits)
{
    // Big-endian bit extraction: bit 0 = MSB of byte 0.
    // Convert to byte offset and bit position within that byte.
    uint byte_off = bit_offset / 8;
    uint bit_off  = bit_offset % 8;

    // Compute minimum bytes needed to cover the bit range.
    // Must not exceed 4 to avoid 32-bit overflow.
    uint bytes_needed = (bit_off + num_bits + 7) / 8;
    if (bytes_needed > 4) bytes_needed = 4;

    // Gather the required bytes.
    uint val = 0;
    for (uint i = 0; i < bytes_needed && (byte_off + i) < data_len; i++) {
        val = (val << 8) | (uint)data[byte_off + i];
    }

    // Number of usable bits we loaded.
    uint loaded_bytes = min(bytes_needed, data_len - byte_off);
    uint loaded_bits  = loaded_bytes * 8;

    // Shift right to align the desired window to the LSB.
    if (loaded_bits >= bit_off + num_bits) {
        val >>= (loaded_bits - bit_off - num_bits);
    }

    // Mask to the desired width.
    val &= ((1u << num_bits) - 1);

    return val;
}

inline uint extract_bits_global(const __global uchar* data, uint data_len,
                                uint bit_offset, uint num_bits)
{
    uint byte_off = bit_offset / 8;
    uint bit_off  = bit_offset % 8;

    uint bytes_needed = (bit_off + num_bits + 7) / 8;
    if (bytes_needed > 4) bytes_needed = 4;

    uint val = 0;
    for (uint i = 0; i < bytes_needed && (byte_off + i) < data_len; i++) {
        val = (val << 8) | (uint)data[byte_off + i];
    }

    uint loaded_bytes = min(bytes_needed, data_len - byte_off);
    uint loaded_bits  = loaded_bytes * 8;
    if (loaded_bits >= bit_off + num_bits) {
        val >>= (loaded_bits - bit_off - num_bits);
    }
    val &= ((1u << num_bits) - 1);

    return val;
}

inline uint extract_bits_local(const __local uchar* data, uint data_len,
                               uint bit_offset, uint num_bits)
{
    uint byte_off = bit_offset / 8;
    uint bit_off  = bit_offset % 8;

    uint bytes_needed = (bit_off + num_bits + 7) / 8;
    if (bytes_needed > 4) bytes_needed = 4;

    uint val = 0;
    for (uint i = 0; i < bytes_needed && (byte_off + i) < data_len; i++) {
        val = (val << 8) | (uint)data[byte_off + i];
    }

    uint loaded_bytes = min(bytes_needed, data_len - byte_off);
    uint loaded_bits  = loaded_bytes * 8;
    if (loaded_bits >= bit_off + num_bits) {
        val >>= (loaded_bits - bit_off - num_bits);
    }
    val &= ((1u << num_bits) - 1);

    return val;
}

#endif // COMMON_CL
