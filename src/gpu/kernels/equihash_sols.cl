// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// equihash_sols.cl -- Equihash (200,9) GPU miner: solution extraction
// =========================================================================
//
// After all 9 collision rounds, the final table (table 9) contains entries
// whose first 180 bits of XOR'd hash are zero.  A valid Equihash solution
// requires ALL 200 bits to XOR to zero.
//
// This kernel scans the final table for entries where the remaining 20 bits
// (bits 180..199) are also zero.  Since we only store 24 bytes (192 bits)
// of hash data, we can check bits 180..191 (the 12 bits we have).  The
// missing 8 bits (192..199) may cause rare false positives, caught by CPU.
//
// For each candidate solution:
//   1. Verify that bits [180..192) of the XOR'd hash are zero.
//   2. Trace back through 9 levels of pair references to recover 512
//      original Equihash indices.
//   3. Validate the ordering constraint at each merge level:
//      the minimum index of the left subtree must be less than the
//      minimum index of the right subtree.
//   4. Pack the 512 indices as 21-bit big-endian values into 1344 bytes.
//   5. Write the packed solution to the solutions output buffer.
//
// Reference tracing:
//   Table 9 entries have (ref0, ref1) pointing to table 8 entries.
//   Table 8 entries have (ref0, ref1) pointing to table 7 entries.
//   ...
//   Table 1 entries have (ref0, ref1) pointing to table 0 entries.
//   Table 0 entries have the original index in bytes [28..31].
//
//   Each ref value is: bucket * MAX_SLOTS + slot_index_in_bucket.
//   Byte offset in the table: ref * SLOT_SIZE.
//
// Kernel launch:
//   Global work size: total entries in table 9 (sum of all bucket counts)
//     OR: NUM_BUCKETS, with each work item scanning its bucket.
//   We use the latter approach: each work item scans one bucket.
//
//   Local work size: 1
//
// Arguments:
//   tables[0..9]         -- pointers to all 10 table slot buffers
//   bucket_counts[9]     -- bucket counts for the final table (table 9)
//   solutions            -- output buffer for packed solutions
//   solution_count       -- atomic counter for number of solutions found
// =========================================================================

// common.cl is prepended by the host at runtime

// -------------------------------------------------------------------------
// Trace back through the collision tree to recover 512 original indices.
//
// The recursion has depth 9 (from table 9 down to table 0).  We use an
// iterative approach with a stack to avoid deep recursion on the GPU.
//
// The stack holds (table_level, ref) pairs.  We process in DFS order
// to fill the indices array left-to-right.
//
// indices[]: output array of 512 uint32 values (original Equihash indices)
// Returns: true if all 512 indices were successfully recovered.
// -------------------------------------------------------------------------

inline bool trace_back(
    __global const uchar* table0,
    __global const uchar* table1,
    __global const uchar* table2,
    __global const uchar* table3,
    __global const uchar* table4,
    __global const uchar* table5,
    __global const uchar* table6,
    __global const uchar* table7,
    __global const uchar* table8,
    uint ref0_final,       // ref0 from the table 9 entry
    uint ref1_final,       // ref1 from the table 9 entry
    uint indices[512],     // output: 512 original indices
    uchar* byte24_xor     // output: XOR of byte 24 from all 512 leaf hashes
)
{
    // Stack for iterative DFS traversal.
    // Maximum depth = 9 rounds (table 8 down to table 0).
    // At each level, we push two children.
    // Max stack depth = 9 * 2 = 18 (but actually at most 10 since we
    // process one side completely before the other).
    // Use a simple stack of (level, ref) pairs.

    // For Equihash (200,9): 2^9 = 512 leaves.
    // We use a stack-based in-order traversal.

    // Stack entry: (level, ref)
    // level 8 = table 8, level 0 = table 0
    // At level 0, the entry has the original index (leaf).

    struct StackEntry {
        uint level;  // which table to read from (0..8)
        uint ref;    // slot reference in that table
    };

    struct StackEntry stack[512];  // Worst case
    int sp = 0;
    uint idx_pos = 0;
    *byte24_xor = 0;  // Initialize XOR accumulator

    // Push the two children from table 9 in reverse order (right first)
    // so that left is processed first (LIFO).
    stack[sp].level = 8; stack[sp].ref = ref1_final; sp++;
    stack[sp].level = 8; stack[sp].ref = ref0_final; sp++;

    while (sp > 0 && idx_pos < 512) {
        sp--;
        uint level = stack[sp].level;
        uint ref   = stack[sp].ref;

        // Compute byte offset into the appropriate table.
        uint byte_offset = ref * SLOT_SIZE;

        if (level == 0) {
            // Leaf: table 0 entry has original index at bytes [28..31].
            // Also accumulate byte 24 (the 25th hash byte lost in collision tables).
            __global const uchar* entry = table0 + byte_offset;
            indices[idx_pos] = read_le32(entry + 28);
            *byte24_xor ^= entry[24];
            idx_pos++;
        } else {
            // Internal node: read ref0 and ref1.
            __global const uchar* entry;
            switch (level) {
                case 1: entry = table1 + byte_offset; break;
                case 2: entry = table2 + byte_offset; break;
                case 3: entry = table3 + byte_offset; break;
                case 4: entry = table4 + byte_offset; break;
                case 5: entry = table5 + byte_offset; break;
                case 6: entry = table6 + byte_offset; break;
                case 7: entry = table7 + byte_offset; break;
                case 8: entry = table8 + byte_offset; break;
                default: return false;
            }

            // Rounds 1+ store ref0 at bytes [24..27], ref1 at bytes [28..31].
            uint child_ref0 = read_le32(entry + 24);
            uint child_ref1 = read_le32(entry + 28);

            // Push right child first (so left is processed first).
            if (sp + 2 > 512) return false;  // Stack overflow check.
            stack[sp].level = level - 1; stack[sp].ref = child_ref1; sp++;
            stack[sp].level = level - 1; stack[sp].ref = child_ref0; sp++;
        }
    }

    return (idx_pos == 512);
}

// -------------------------------------------------------------------------
// Normalize the ordering of indices.
//
// The GPU collision rounds create pairs without enforcing the ordering
// invariant.  This function swaps subtrees bottom-up at each level so
// that min(left_half) < min(right_half), which is the canonical form
// required by Equihash verification.
//
// Must be called before check_ordering() (which then becomes a no-op
// sanity check) and before pack_solution().
// -------------------------------------------------------------------------

inline void normalize_ordering(uint indices[512])
{
    for (uint level = 0; level < EQ_K; level++) {
        uint pair_size = 1u << (level + 1);
        uint half_sz = pair_size / 2;

        for (uint i = 0; i < 512; i += pair_size) {
            // Find min of left half [i .. i+half_sz).
            uint left_min = indices[i];
            for (uint j = i + 1; j < i + half_sz; j++) {
                if (indices[j] < left_min) left_min = indices[j];
            }

            // Find min of right half [i+half_sz .. i+pair_size).
            uint right_min = indices[i + half_sz];
            for (uint j = i + half_sz + 1; j < i + pair_size; j++) {
                if (indices[j] < right_min) right_min = indices[j];
            }

            // Swap halves if ordering is violated.
            if (left_min > right_min) {
                for (uint j = 0; j < half_sz; j++) {
                    uint tmp = indices[i + j];
                    indices[i + j] = indices[i + half_sz + j];
                    indices[i + half_sz + j] = tmp;
                }
            }
        }
    }
}

// -------------------------------------------------------------------------
// Validate the ordering constraint.
//
// At each level j (0..k-1) of the binary tree:
//   - Pairs are of size 2^(j+1).
//   - The minimum index in the left half_sz must be less than the minimum
//     index in the right half_sz.
//
// This matches the CPU's check_ordering() function.
// After normalize_ordering(), this should always pass (sanity check).
// Returns true if ordering is valid.
// -------------------------------------------------------------------------

inline bool check_ordering(uint indices[512])
{
    for (uint level = 0; level < EQ_K; level++) {
        uint pair_size = 1u << (level + 1);
        uint half_sz = pair_size / 2;

        for (uint i = 0; i < 512; i += pair_size) {
            // Find min of left half_sz [i .. i+half_sz).
            uint left_min = indices[i];
            for (uint j = i + 1; j < i + half_sz; j++) {
                if (indices[j] < left_min) left_min = indices[j];
            }

            // Find min of right half_sz [i+half_sz .. i+pair_size).
            uint right_min = indices[i + half_sz];
            for (uint j = i + half_sz + 1; j < i + pair_size; j++) {
                if (indices[j] < right_min) right_min = indices[j];
            }

            if (left_min >= right_min) return false;
        }
    }

    return true;
}

// -------------------------------------------------------------------------
// Check that all indices are distinct.
// We use a simple brute-force check since we're on GPU.
// For 512 indices, this is 512*511/2 = ~131K comparisons.
//
// Optimization: since valid solutions have a specific tree structure,
// duplicates are extremely rare.  We can use a bitmap for indices < 2^21.
// But 2^21 bits = 256KB -- too large for private memory.
//
// Instead, we sort and check for adjacent duplicates.
// Simple insertion sort for 512 elements (adequate for GPU work items
// that process very few candidates).
// -------------------------------------------------------------------------

inline bool check_distinct(uint indices[512])
{
    // Copy for sorting (we don't want to modify the original).
    uint sorted[512];
    for (int i = 0; i < 512; i++) {
        sorted[i] = indices[i];
    }

    // Simple shell sort (faster than insertion sort for 512 elements).
    for (uint gap = 256; gap > 0; gap >>= 1) {
        for (uint i = gap; i < 512; i++) {
            uint tmp = sorted[i];
            uint j = i;
            while (j >= gap && sorted[j - gap] > tmp) {
                sorted[j] = sorted[j - gap];
                j -= gap;
            }
            sorted[j] = tmp;
        }
    }

    for (int i = 1; i < 512; i++) {
        if (sorted[i] == sorted[i - 1]) return false;
    }

    return true;
}

// -------------------------------------------------------------------------
// Pack 512 indices into a 1344-byte solution.
//
// Each index is INDEX_BITS (21) bits wide.  Indices are packed MSB-first
// into a contiguous byte stream, matching the CPU's pack_indices().
//
// Total bits: 512 * 21 = 10752
// Total bytes: (10752 + 7) / 8 = 1344
// -------------------------------------------------------------------------

inline void pack_solution(uint indices[512], uchar solution[SOLUTION_SIZE])
{
    // Zero-initialize output.
    for (int i = 0; i < SOLUTION_SIZE; i++) {
        solution[i] = 0;
    }

    uint bit_pos = 0;
    for (int i = 0; i < 512; i++) {
        uint idx = indices[i];

        // Write INDEX_BITS (21) bits of idx, MSB first.
        for (int b = INDEX_BITS - 1; b >= 0; b--) {
            if ((idx >> b) & 1) {
                uint byte_idx = bit_pos / 8;
                uint bit_idx  = 7 - (bit_pos % 8);
                solution[byte_idx] |= (uchar)(1u << bit_idx);
            }
            bit_pos++;
        }
    }
}

// -------------------------------------------------------------------------
// Main solution extraction kernel
//
// Each work item processes one bucket of the final table (table 9).
// -------------------------------------------------------------------------

__kernel void equihash_sols(
    __global const uchar*  table0,          // init table
    __global const uchar*  table1,          // round 0 output
    __global const uchar*  table2,          // round 1 output
    __global const uchar*  table3,          // round 2 output
    __global const uchar*  table4,          // round 3 output
    __global const uchar*  table5,          // round 4 output
    __global const uchar*  table6,          // round 5 output
    __global const uchar*  table7,          // round 6 output
    __global const uchar*  table8,          // round 7 output
    __global const uchar*  table9,          // round 8 output (final)
    __global const uint*   final_bucket_counts, // table 9 bucket counts
    __global       uchar*  solutions,       // output: packed solutions
    __global       uint*   solution_count,  // output: number of solutions
    __global       uint*   diag_counters    // diagnostic: [hash_pass, trace_pass, distinct_pass, order_pass]
)
{
    uint bucket = get_global_id(0);
    if (bucket >= NUM_BUCKETS) return;

    uint count = final_bucket_counts[bucket];
    if (count > MAX_SLOTS) count = MAX_SLOTS;

    // Base offset for this bucket in table 9.
    uint base_offset = bucket * MAX_SLOTS;

    for (uint s = 0; s < count; s++) {
        // Early exit if we already have enough solutions.
        // Note: we still need to scan all entries for byte24 filtering,
        // but once MAX_SOLUTIONS valid ones are found, we can stop.
        if (*solution_count >= MAX_SOLUTIONS) return;

        uint slot_byte = (base_offset + s) * SLOT_SIZE;
        __global const uchar* entry = table9 + slot_byte;

        // ---- Check the remaining collision bits ----
        //
        // After 9 rounds of 20-bit collisions, 180 bits have been matched.
        // The remaining 20 bits (bits 180..199 of the original 200-bit hash)
        // must also be zero for a valid solution.
        //
        // In the final table, the XOR'd hash is stored in bytes [0..23].
        // Bits 180..191 are within these 24 bytes.  Bits 192..199 are not
        // stored (we only keep 24 bytes = 192 bits).
        //
        // We check bits 180..191 (the 12 bits we have access to).
        // False positives from the missing 8 bits are caught by CPU verify.
        //
        // Bit 180 = byte 22 bit 4, bit 191 = byte 23 bit 7.
        //
        // Actually, bits are big-endian: bit N is at byte N/8, position
        // 7-(N%8) within the byte.
        //
        // Bit 180: byte 180/8=22, position 7-(180%8)=7-4=3 -> mask 0x08
        //   Bits 180..183 = byte 22, bits 3..0 (lower nibble)
        // Bit 184: byte 184/8=23, position 7-(184%8)=7-0=7
        //   Bits 184..191 = byte 23, all 8 bits
        //
        // So: check that (entry[22] & 0x0F) == 0 && entry[23] == 0.

        if ((entry[22] & 0x0F) != 0) continue;
        if (entry[23] != 0) continue;

        // This entry is a candidate solution.  Trace back to get indices.
        atomic_inc(&diag_counters[0]);  // hash_pass

        uint ref0 = read_le32(entry + 24);
        uint ref1 = read_le32(entry + 28);

        uint indices[512];
        uchar b24_xor = 0;
        bool ok = trace_back(
            table0, table1, table2, table3, table4,
            table5, table6, table7, table8,
            ref0, ref1, indices, &b24_xor);

        if (!ok) continue;
        atomic_inc(&diag_counters[1]);  // trace_pass

        // Normalize ordering: swap subtrees so min(left) < min(right).
        normalize_ordering(indices);

        // Validate distinctness.
        if (!check_distinct(indices)) continue;
        atomic_inc(&diag_counters[2]);  // distinct_pass

        // Validate ordering constraint.
        if (!check_ordering(indices)) continue;
        atomic_inc(&diag_counters[3]);  // order_pass

        // Check byte 24 XOR: bits 192..199 of the full 200-bit collision.
        // The collision tables only store 24 bytes (192 bits), so byte 24
        // is recovered by XOR'ing byte 24 from all 512 leaf entries.
        // Only output solutions where all 200 bits are zero.
        atomic_inc(&diag_counters[6]);  // total candidates checked
        if (b24_xor != 0) continue;
        atomic_inc(&diag_counters[5]);  // byte24_pass

        // Pack and output the solution.
        uchar packed[SOLUTION_SIZE];
        pack_solution(indices, packed);

        uint sol_idx = atomic_inc(solution_count);
        if (sol_idx < MAX_SOLUTIONS) {
            __global uchar* dst = solutions + sol_idx * SOLUTION_SIZE;
            for (int i = 0; i < SOLUTION_SIZE; i++) {
                dst[i] = packed[i];
            }
        }
    }
}
