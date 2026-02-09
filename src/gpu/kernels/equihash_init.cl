// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// equihash_init.cl -- Equihash (200,9) GPU miner: initial hash generation
// =========================================================================
//
// This kernel generates the 2^21 = 2,097,152 initial hashes and distributes
// them into buckets for the first collision round.
//
// For each index i in [0, 2^21):
//   H(i) = SHA3-256(equihash_input[32] || le32(i))[0:25]
//
// where equihash_input = keccak256(serialized_80byte_header).
//
// The 25-byte hash is then bucketed by its top BUCKET_BITS (12) bits
// (treated as a big-endian bit stream) and written into the corresponding
// bucket slot in the init table (table region 0).
//
// Slot layout (32 bytes):
//   bytes [ 0..24] : hash[25]       -- the 25-byte SHA3-256 output
//   bytes [25..27] : padding (0)
//   bytes [28..31] : index (uint32)  -- the original Equihash index i
//
// Kernel launch:
//   Global work size:  NUM_INDICES (2,097,152)
//   Local work size:   any (e.g. 256)
//
// Arguments:
//   input32        -- 32-byte equihash input (constant)
//   slots          -- output slot buffer for table 0
//   bucket_counts  -- per-bucket atomic counters (NUM_BUCKETS uint32s)
// =========================================================================

// common.cl and keccak256.cl are prepended by the host at runtime

__kernel void equihash_init(
    __global const uchar*  input32,         // 32-byte equihash input
    __global       uchar*  slots,           // table 0 slot data
    __global       uint*   bucket_counts    // per-bucket counters
)
{
    uint index = get_global_id(0);

    // Bounds check (should not trigger with correct launch size).
    if (index >= NUM_INDICES) return;

    // ---- Step 1: Compute SHA3-256(input32 || le32(index))[0:25] ----

    // Cache the 32-byte input in private memory for faster access.
    uchar input_priv[32];
    for (int i = 0; i < 32; i++) {
        input_priv[i] = input32[i];
    }

    uchar hash[25];
    sha3_256_36bytes_priv(input_priv, index, hash);

    // ---- Step 2: Determine the bucket ----
    //
    // The CPU code's bucket_key() extracts collision bits as a big-endian
    // bit stream from the hash.  For round 0, the collision window is
    // bits [0..20) of the 200-bit hash.  We use the top BUCKET_BITS (12)
    // of those 20 bits as the bucket key.
    //
    // Big-endian extraction: bit 0 is the MSB of byte 0.
    // Top 12 bits of the 200-bit hash = bits [0..12) = first 12 bits.
    //
    // Extract from bytes 0..1:
    //   bits 0..7  = hash[0] (MSB first)
    //   bits 8..15 = hash[1]
    //   We need bits 0..11 = hash[0] << 4 | hash[1] >> 4

    uint bucket = ((uint)hash[0] << 4) | ((uint)hash[1] >> 4);

    // ---- Step 3: Atomically allocate a slot in the bucket ----

    uint slot_idx = atomic_inc(&bucket_counts[bucket]);

    // Skip write if the bucket is full (overflow protection).
    if (slot_idx >= MAX_SLOTS) return;

    // ---- Step 4: Write the slot data ----
    //
    // Compute the byte offset into the slots buffer:
    //   offset = (bucket * MAX_SLOTS + slot_idx) * SLOT_SIZE

    uint slot_offset = ((uint)bucket * MAX_SLOTS + slot_idx) * SLOT_SIZE;
    __global uchar* dst = slots + slot_offset;

    // Write 25 hash bytes.
    for (int i = 0; i < 25; i++) {
        dst[i] = hash[i];
    }

    // Write 3 padding bytes.
    dst[25] = 0;
    dst[26] = 0;
    dst[27] = 0;

    // Write the original index as little-endian uint32.
    write_le32(dst + 28, index);
}
