// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// equihash_round.cl -- Equihash (200,9) GPU miner: collision round kernel
// =========================================================================
//
// This kernel performs one Wagner collision round.  It is invoked 9 times
// (round 0 through round 8) to process the 9 collision rounds of
// Equihash (200,9).
//
// At each round r:
//   - The source table was bucketed on the top BUCKET_BITS (12) of the
//     r-th 20-bit collision window (bits [r*20 .. r*20+12)).
//   - Within each bucket, entries already share those 12 bits.
//   - We compare the remaining INTRA_BITS (8) bits of the r-th collision
//     window (bits [r*20+12 .. (r+1)*20)) to find colliding pairs.
//   - For each colliding pair, we XOR their hash data and write the
//     result to the destination table, bucketed on the top 12 bits of
//     the NEXT collision window (bits [(r+1)*20 .. (r+1)*20+12)).
//
// Slot format for the source table:
//   Round 0 (from init kernel):
//     bytes [0..24]  = 25-byte hash
//     bytes [25..27] = padding
//     bytes [28..31] = original index (uint32)
//
//   Rounds 1+ (from previous collision round):
//     bytes [0..23]  = 24 bytes of XOR'd hash data
//     bytes [24..27] = ref0 (uint32) -- left parent slot
//     bytes [28..31] = ref1 (uint32) -- right parent slot
//
// Slot format for the destination table (always rounds 1+):
//     bytes [0..23]  = 24 bytes of XOR'd hash data
//     bytes [24..27] = ref0 (uint32) -- left parent in source table
//     bytes [28..31] = ref1 (uint32) -- right parent in source table
//
// The ref values encode the source table position as:
//   ref = src_bucket * MAX_SLOTS + src_slot_index
// This allows the solution extraction kernel to trace back through all
// rounds to recover the 512 original indices.
//
// Kernel launch:
//   Global work size:  NUM_BUCKETS (4096)
//   Local work size:   1  (each work item processes one bucket)
//
// Note: We use one work item per bucket (not a work-group) for simplicity.
// Each work item iterates over all entries in its source bucket, builds a
// local hash table on the 8 intra-bucket collision bits, and processes
// all colliding pairs.  This is efficient because bucket occupancy averages
// ~512 entries (max 684).
//
// Arguments:
//   round             -- current round number (0..8)
//   src_slots         -- source table slot data (read)
//   src_bucket_counts -- source per-bucket counts (read)
//   dst_slots         -- destination table slot data (write)
//   dst_bucket_counts -- destination per-bucket counts (read-write, atomic)
// =========================================================================

// common.cl is prepended by the host at runtime

// -------------------------------------------------------------------------
// Hash table for intra-bucket collision finding
//
// We use a simple open-addressing hash table indexed by the 8 intra-bucket
// collision bits (256 possible values).  Each bin holds a list of slot
// indices sharing that value.  Since multiple entries can collide on the
// same 8 bits, we use a "next" linked list within a fixed pool.
// -------------------------------------------------------------------------

#define INTRA_TABLE_SIZE  256       // 2^INTRA_BITS
#define MAX_ENTRIES_PER_BIN 32      // max chain length before we stop

// -------------------------------------------------------------------------
// Helper: extract the hash data pointer and length for a given round
//
// For round 0 (init table): hash is 25 bytes at offset 0
// For rounds 1+:            hash is 24 bytes at offset 0
// -------------------------------------------------------------------------

inline uint get_hash_len(uint round) {
    return (round == 0) ? HASH_LEN : 24;
}

// -------------------------------------------------------------------------
// Helper: extract N bits from a hash starting at a given bit offset
// (big-endian bit ordering, matching the CPU's bucket_key function)
// -------------------------------------------------------------------------

inline uint extract_hash_bits(__global const uchar* hash_data,
                              uint hash_byte_len,
                              uint bit_offset,
                              uint num_bits)
{
    uint byte_off = bit_offset / 8;
    uint bit_off  = bit_offset % 8;

    // Gather up to 4 bytes to cover the desired range.
    uint val = 0;
    uint bytes_needed = (bit_off + num_bits + 7) / 8;
    for (uint i = 0; i < bytes_needed && (byte_off + i) < hash_byte_len; i++) {
        val = (val << 8) | (uint)hash_data[byte_off + i];
    }

    // Align: shift right to place desired bits at LSB.
    uint loaded_bits = min(bytes_needed, hash_byte_len - byte_off) * 8;
    if (loaded_bits >= bit_off + num_bits) {
        val >>= (loaded_bits - bit_off - num_bits);
    }
    val &= ((1u << num_bits) - 1);

    return val;
}

// -------------------------------------------------------------------------
// Main collision round kernel
// -------------------------------------------------------------------------

__kernel void equihash_round(
    uint                         round,             // 0..8
    __global const uchar*        src_slots,         // source table
    __global const uint*         src_bucket_counts, // source counts
    __global       uchar*        dst_slots,         // destination table
    __global       uint*         dst_bucket_counts  // destination counts
)
{
    uint bucket = get_global_id(0);
    if (bucket >= NUM_BUCKETS) return;

    // Number of entries in this source bucket.
    uint count = src_bucket_counts[bucket];
    if (count > MAX_SLOTS) count = MAX_SLOTS;
    if (count < 2) return;  // Need at least 2 for a pair.

    // ---- Determine bit offsets for this round ----
    //
    // The r-th collision window spans bits [r*20 .. (r+1)*20) of the
    // original 200-bit hash.
    //
    // In the init table (round 0), the hash is stored as-is (25 bytes).
    // The top 12 bits were used for bucketing.
    //
    // In collision tables (rounds 1+), the hash is stored as the XOR of
    // parent hashes.  Since the XOR zeroes out the bits that were matched
    // in previous rounds, the "consumed" leading bits are all zero.
    // However, we still store the full hash (24 bytes for rounds 1+),
    // so bit offsets remain the same as in the original hash.
    //
    // For round r:
    //   collision_bit_start = r * COLLISION_BITS = r * 20
    //   The bucket bits are [collision_bit_start .. collision_bit_start + 12)
    //   The intra-bucket bits are [collision_bit_start + 12 .. collision_bit_start + 20)

    uint collision_bit_start = round * COLLISION_BITS;
    uint intra_bit_start     = collision_bit_start + BUCKET_BITS;

    // Hash data length for current round.
    uint hash_len = get_hash_len(round);

    // ---- Phase 1: Build a table of intra-bucket collision values ----
    //
    // For each entry in the bucket, extract the 8 intra-bucket collision
    // bits and group entries by this value.  We use arrays indexed by the
    // 8-bit value (256 bins), with each bin storing up to MAX_ENTRIES_PER_BIN
    // slot indices.

    // We process pairs by iterating: for each entry, look up all previous
    // entries with the same intra-bits value.

    // Storage for bin chains: for each of 256 possible intra-bit values,
    // we store up to MAX_ENTRIES_PER_BIN source slot indices.
    // Total private storage: 256 * 32 * 4 = 32KB -- too large for private.
    // Instead, do a simpler O(n^2) scan, but group by intra-bits.

    // Simpler approach: iterate over all pairs, but use a hash table to
    // quickly find entries with matching intra-bits.
    //
    // We'll build a flat array of (intra_val, slot_idx) pairs, sorted by
    // intra_val.  Then for each group of equal intra_val, emit all pairs.
    //
    // For memory efficiency, since count <= 684, we use a two-pass approach:
    // Pass 1: count entries per intra_val.
    // Pass 2: for each intra_val with >= 2 entries, iterate and emit pairs.

    // Actually, the simplest approach that fits in private memory:
    // For each pair of entries (i, j), check if their intra bits match.
    // This is O(n^2) but n <= 684, so ~234K comparisons per bucket.
    // With 4096 buckets * 234K = ~960M comparisons total -- too slow.
    //
    // Better approach: build a compact index using the 256 bins.
    // We store up to 684 entries total. For each bin, store a start+count.

    // Use private arrays: 256 bin counts (1KB) + 684 entry array (2.7KB).
    // Overflow: entries beyond MAX_ENTRIES_PER_BIN in a bin are dropped.

    // Bin counts for 256 intra-bit values.
    ushort bin_count[INTRA_TABLE_SIZE];
    for (int i = 0; i < INTRA_TABLE_SIZE; i++) {
        bin_count[i] = 0;
    }

    // First pass: count entries per bin.
    uint base_offset = bucket * MAX_SLOTS;
    for (uint s = 0; s < count; s++) {
        uint slot_byte_offset = (base_offset + s) * SLOT_SIZE;
        __global const uchar* src = src_slots + slot_byte_offset;
        uint intra = extract_hash_bits(src, hash_len, intra_bit_start, INTRA_BITS);
        if (bin_count[intra] < MAX_ENTRIES_PER_BIN) {
            bin_count[intra]++;
        }
    }

    // Compute prefix sums for bin offsets.
    ushort bin_offset[INTRA_TABLE_SIZE];
    ushort total = 0;
    for (int i = 0; i < INTRA_TABLE_SIZE; i++) {
        bin_offset[i] = total;
        total += bin_count[i];
    }

    // Second pass: fill the sorted entry list.
    // We store the slot index within the bucket for each entry.
    // Reset counts for reuse as insertion cursors.
    ushort sorted_entries[MAX_SLOTS];
    ushort bin_cursor[INTRA_TABLE_SIZE];
    for (int i = 0; i < INTRA_TABLE_SIZE; i++) {
        bin_cursor[i] = bin_offset[i];
    }

    for (uint s = 0; s < count; s++) {
        uint slot_byte_offset = (base_offset + s) * SLOT_SIZE;
        __global const uchar* src = src_slots + slot_byte_offset;
        uint intra = extract_hash_bits(src, hash_len, intra_bit_start, INTRA_BITS);
        ushort cursor = bin_cursor[intra];
        if (cursor < bin_offset[intra] + bin_count[intra]) {
            sorted_entries[cursor] = (ushort)s;
            bin_cursor[intra] = cursor + 1;
        }
    }

    // ---- Phase 2: Process colliding pairs and write to destination ----
    //
    // For each bin with >= 2 entries, iterate over all pairs within the bin.
    // For each pair (a, b) with a < b:
    //   1. XOR their hash data
    //   2. Compute the bucket key for the next round from the XOR'd hash
    //   3. Atomically allocate a destination slot
    //   4. Write the XOR'd hash + ref0/ref1

    // Bit offset for the next round's bucket key.
    uint next_collision_start = (round + 1) * COLLISION_BITS;

    for (int bin = 0; bin < INTRA_TABLE_SIZE; bin++) {
        ushort bcount = bin_count[bin];
        if (bcount < 2) continue;

        ushort bstart = bin_offset[bin];

        for (ushort a = 0; a < bcount; a++) {
            uint sa = sorted_entries[bstart + a];
            uint sa_byte = (base_offset + sa) * SLOT_SIZE;
            __global const uchar* src_a = src_slots + sa_byte;

            for (ushort b = a + 1; b < bcount; b++) {
                uint sb = sorted_entries[bstart + b];
                uint sb_byte = (base_offset + sb) * SLOT_SIZE;
                __global const uchar* src_b = src_slots + sb_byte;

                // XOR the hash data (first 24 bytes, regardless of round).
                // For round 0, we use 25 bytes but store only 24 in output.
                uchar xor_hash[24];
                uint xor_len = min(hash_len, 24u);
                for (uint i = 0; i < xor_len; i++) {
                    xor_hash[i] = src_a[i] ^ src_b[i];
                }
                // Zero-pad if hash_len < 24.
                for (uint i = xor_len; i < 24; i++) {
                    xor_hash[i] = 0;
                }

                // For the final round (round 8), we don't need to bucket
                // the output -- the solution kernel will scan the table.
                // But for consistency, we still bucket it.

                // Extract the next round's bucket key from the XOR'd hash.
                // The bit offset is next_collision_start, and we need
                // BUCKET_BITS (12) bits.
                //
                // Special case: if next_collision_start + BUCKET_BITS > 192
                // (= 24 bytes * 8), we don't have enough hash data.
                // This happens at round 8: next_collision_start = 180,
                // 180 + 12 = 192 -- exactly at the boundary, so it's OK.
                // Round 8 output would need bits 180..191 = last 12 bits
                // of the 24-byte XOR hash, which we have.

                uint dst_bucket;
                if (next_collision_start + BUCKET_BITS <= 192) {
                    dst_bucket = extract_bits(xor_hash, 24,
                                              next_collision_start,
                                              BUCKET_BITS);
                } else {
                    // Insufficient hash data; use bucket 0 as fallback.
                    // This should not happen with our parameters.
                    dst_bucket = 0;
                }

                // Atomically allocate a destination slot.
                uint dst_slot_idx = atomic_inc(&dst_bucket_counts[dst_bucket]);
                if (dst_slot_idx >= MAX_SLOTS) continue;  // Bucket full.

                // Compute destination byte offset.
                uint dst_byte = ((uint)dst_bucket * MAX_SLOTS + dst_slot_idx) * SLOT_SIZE;
                __global uchar* dst = dst_slots + dst_byte;

                // Write XOR'd hash (24 bytes).
                for (uint i = 0; i < 24; i++) {
                    dst[i] = xor_hash[i];
                }

                // Write ref0 and ref1 as source table positions.
                // ref = bucket * MAX_SLOTS + slot_index_in_bucket
                uint ref0 = base_offset + sa;
                uint ref1 = base_offset + sb;
                write_le32(dst + 24, ref0);
                write_le32(dst + 28, ref1);
            }
        }
    }
}
