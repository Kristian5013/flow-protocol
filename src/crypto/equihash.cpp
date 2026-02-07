// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/equihash.h"
#include "crypto/keccak.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <unordered_map>

namespace crypto {

namespace {

// ===================================================================
// Hash generation
// ===================================================================

/// Generate the i-th hash output using Keccak-256 in counter mode.
/// Produces params.hash_output() bytes of output for index i.
///
/// H(input, i) = truncate(Keccak256(input || le32(i / hashes_per)),
///               hash_output)[offset .. offset + hash_output]
///
/// For n=200 (25 bytes output), a single Keccak-256 (32 bytes) can
/// yield one hash output per invocation.
std::vector<uint8_t> generate_hash(
    const EquihashParams& params,
    std::span<const uint8_t> input,
    uint32_t index) {
    size_t hash_len = params.hash_output();
    size_t hashes_per_block = 32 / hash_len;
    if (hashes_per_block == 0) hashes_per_block = 1;

    uint32_t block_index = index / static_cast<uint32_t>(
        hashes_per_block);
    uint32_t offset_in_block = index % static_cast<uint32_t>(
        hashes_per_block);

    // Build pre-image: input || le32(block_index).
    std::vector<uint8_t> preimage(input.size() + 4);
    std::memcpy(preimage.data(), input.data(), input.size());
    preimage[input.size() + 0] =
        static_cast<uint8_t>(block_index & 0xFF);
    preimage[input.size() + 1] =
        static_cast<uint8_t>((block_index >> 8) & 0xFF);
    preimage[input.size() + 2] =
        static_cast<uint8_t>((block_index >> 16) & 0xFF);
    preimage[input.size() + 3] =
        static_cast<uint8_t>((block_index >> 24) & 0xFF);

    core::uint256 digest = keccak256(
        std::span<const uint8_t>(preimage));

    std::vector<uint8_t> result(hash_len);
    size_t byte_offset = offset_in_block * hash_len;
    if (byte_offset + hash_len > 32) {
        // Wrap: generate next block too and concatenate.
        // For typical params this won't happen (25 <= 32).
        byte_offset = 0;
    }
    std::memcpy(result.data(),
        digest.data() + byte_offset, hash_len);

    return result;
}

// ===================================================================
// Solution bit-packing / unpacking
// ===================================================================

/// Pack a vector of indices into a tightly-packed bit stream.
/// Each index occupies index_bit_length bits.
std::vector<uint8_t> pack_indices(
    const std::vector<uint32_t>& indices,
    unsigned bit_len) {
    size_t total_bits = indices.size() * bit_len;
    size_t total_bytes = (total_bits + 7) / 8;
    std::vector<uint8_t> packed(total_bytes, 0);

    size_t bit_pos = 0;
    for (uint32_t idx : indices) {
        // Write bit_len bits of idx into packed[], MSB first.
        for (int b = static_cast<int>(bit_len) - 1; b >= 0; --b) {
            if ((idx >> b) & 1) {
                size_t byte_idx = bit_pos / 8;
                unsigned bit_idx = 7 - (bit_pos % 8);
                packed[byte_idx] |=
                    static_cast<uint8_t>(1u << bit_idx);
            }
            ++bit_pos;
        }
    }

    return packed;
}

/// Unpack a tightly-packed bit stream into a vector of indices.
std::vector<uint32_t> unpack_indices(
    std::span<const uint8_t> packed,
    size_t num_indices,
    unsigned bit_len) {
    std::vector<uint32_t> indices(num_indices, 0);

    size_t bit_pos = 0;
    for (size_t i = 0; i < num_indices; ++i) {
        uint32_t val = 0;
        for (unsigned b = 0; b < bit_len; ++b) {
            size_t byte_idx = bit_pos / 8;
            unsigned bit_idx = 7 - (bit_pos % 8);
            if (byte_idx < packed.size() &&
                (packed[byte_idx] >> bit_idx) & 1) {
                val |= (1u << (bit_len - 1 - b));
            }
            ++bit_pos;
        }
        indices[i] = val;
    }

    return indices;
}

// ===================================================================
// XOR utilities
// ===================================================================

/// XOR two byte vectors of equal length.  Result is written to out.
void xor_bytes(
    std::vector<uint8_t>& out,
    const std::vector<uint8_t>& a,
    const std::vector<uint8_t>& b) {
    assert(a.size() == b.size());
    out.resize(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i] = a[i] ^ b[i];
    }
}

/// Check if the first n_bits of a byte vector are all zero.
bool has_leading_zero_bits(
    const std::vector<uint8_t>& data,
    unsigned n_bits) {
    unsigned full_bytes = n_bits / 8;
    unsigned remaining_bits = n_bits % 8;

    for (unsigned i = 0; i < full_bytes; ++i) {
        if (i >= data.size()) return true;
        if (data[i] != 0) return false;
    }

    if (remaining_bits > 0 && full_bytes < data.size()) {
        uint8_t mask = static_cast<uint8_t>(
            0xFF << (8 - remaining_bits));
        if (data[full_bytes] & mask) return false;
    }

    return true;
}

/// Check if all bytes are zero.
bool is_all_zero(const std::vector<uint8_t>& data) {
    for (uint8_t b : data) {
        if (b != 0) return false;
    }
    return true;
}

// ===================================================================
// Verification internals
// ===================================================================

/// Validate the ordering constraint at each level of the binary tree.
/// At level 0 (leaves), pairs must satisfy indices[2i] < indices[2i+1].
/// At level j, the "representative" of the left subtree must be less
/// than the representative of the right subtree.  The representative
/// is the minimum index in the subtree.
bool check_ordering(
    const std::vector<uint32_t>& indices,
    unsigned k) {
    size_t n = indices.size();
    if (n != (static_cast<size_t>(1) << k)) return false;

    // Check at each level.
    for (unsigned level = 0; level < k; ++level) {
        size_t pair_size = static_cast<size_t>(1) << (level + 1);
        size_t half = pair_size / 2;
        for (size_t i = 0; i < n; i += pair_size) {
            // Find minimum index in left half [i, i+half).
            uint32_t left_min = indices[i];
            for (size_t j = i + 1; j < i + half; ++j) {
                left_min = std::min(left_min, indices[j]);
            }
            // Find minimum index in right half [i+half, i+pair_size).
            uint32_t right_min = indices[i + half];
            for (size_t j = i + half + 1;
                 j < i + pair_size; ++j) {
                right_min = std::min(right_min, indices[j]);
            }
            if (left_min >= right_min) return false;
        }
    }

    return true;
}

/// Check that all indices are distinct.
bool check_distinct(const std::vector<uint32_t>& indices) {
    std::vector<uint32_t> sorted = indices;
    std::sort(sorted.begin(), sorted.end());
    for (size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i] == sorted[i - 1]) return false;
    }
    return true;
}

// ===================================================================
// Solver internals
// ===================================================================

/// A hash table entry for Wagner's algorithm.
struct TableEntry {
    std::vector<uint8_t> hash;         // current XOR value
    std::vector<uint32_t> indices;     // contributing indices
};

/// Extract a collision bucket key from a hash value.  The key is
/// the first collision_byte_length bytes of the hash, interpreted
/// as the bits that should collide in this round.
uint64_t bucket_key(
    const std::vector<uint8_t>& hash,
    unsigned round,
    const EquihashParams& params) {
    unsigned bits_per_round = params.n / (params.k + 1);
    unsigned bit_start = round * bits_per_round;
    unsigned byte_start = bit_start / 8;
    unsigned bit_offset = bit_start % 8;

    // Extract collision_byte_length bytes starting at byte_start.
    uint64_t key = 0;
    size_t cbl = params.collision_byte_length();
    for (size_t i = 0; i < cbl && (byte_start + i) < hash.size();
         ++i) {
        key = (key << 8) | hash[byte_start + i];
    }

    // Shift to align to bit boundary.
    if (bit_offset > 0) {
        key >>= (8 - bit_offset);
        // Mask to exact number of collision bits.
        key &= (static_cast<uint64_t>(1) << bits_per_round) - 1;
    } else {
        // Mask to exact number of collision bits.
        unsigned total_key_bits = static_cast<unsigned>(cbl) * 8;
        if (total_key_bits > bits_per_round) {
            key >>= (total_key_bits - bits_per_round);
        }
    }

    return key;
}

}  // anonymous namespace

// ===================================================================
// Public: Verification
// ===================================================================

bool equihash_verify(
    const EquihashParams& params,
    std::span<const uint8_t> input,
    std::span<const uint8_t> solution) {
    // Basic size check.
    if (solution.size() != params.solution_size()) {
        return false;
    }

    // Decode indices from packed solution.
    size_t num_indices = params.indices_per_solution();
    unsigned bit_len = params.index_bit_length();
    auto indices = unpack_indices(solution, num_indices, bit_len);

    if (indices.size() != num_indices) {
        return false;
    }

    // All indices must be distinct.
    if (!check_distinct(indices)) {
        return false;
    }

    // Check the ordering constraint (binary tree structure).
    if (!check_ordering(indices, params.k)) {
        return false;
    }

    // Generate hashes for each index.
    std::vector<std::vector<uint8_t>> hashes(num_indices);
    for (size_t i = 0; i < num_indices; ++i) {
        hashes[i] = generate_hash(params, input, indices[i]);
    }

    // Verify the collision structure at each Wagner round.
    unsigned bits_per_round = params.n / (params.k + 1);

    for (unsigned round = 0; round < params.k; ++round) {
        size_t pair_size = static_cast<size_t>(1) << (round + 1);

        for (size_t i = 0; i < num_indices; i += pair_size) {
            // XOR the left half and right half results.
            // At round 0, we XOR pairs: hashes[i] ^ hashes[i+1].
            // At round j, we XOR the accumulated XORs of subtrees.

            // Compute XOR of left subtree.
            size_t half = pair_size / 2;
            std::vector<uint8_t> left_xor = hashes[i];
            for (size_t j = i + 1; j < i + half; ++j) {
                std::vector<uint8_t> tmp;
                xor_bytes(tmp, left_xor, hashes[j]);
                left_xor = std::move(tmp);
            }

            // Compute XOR of right subtree.
            std::vector<uint8_t> right_xor = hashes[i + half];
            for (size_t j = i + half + 1;
                 j < i + pair_size; ++j) {
                std::vector<uint8_t> tmp;
                xor_bytes(tmp, right_xor, hashes[j]);
                right_xor = std::move(tmp);
            }

            // The XOR of left and right must have leading zeros.
            std::vector<uint8_t> combined;
            xor_bytes(combined, left_xor, right_xor);

            unsigned required_zero_bits =
                (round + 1) * bits_per_round;
            if (!has_leading_zero_bits(combined,
                    required_zero_bits)) {
                return false;
            }
        }
    }

    // Final check: the XOR of ALL hashes must be zero.
    std::vector<uint8_t> total_xor = hashes[0];
    for (size_t i = 1; i < num_indices; ++i) {
        std::vector<uint8_t> tmp;
        xor_bytes(tmp, total_xor, hashes[i]);
        total_xor = std::move(tmp);
    }

    return is_all_zero(total_xor);
}

// ===================================================================
// Public: Solver
// ===================================================================

std::vector<std::vector<uint8_t>> equihash_solve(
    const EquihashParams& params,
    std::span<const uint8_t> input,
    size_t max_solutions) {
    if (params.k == 0 || params.n == 0) {
        throw std::invalid_argument(
            "equihash_solve: invalid parameters (n=0 or k=0)");
    }

    unsigned bits_per_round = params.n / (params.k + 1);
    unsigned bit_len = params.index_bit_length();
    size_t num_initial = static_cast<size_t>(1) << bit_len;

    std::vector<std::vector<uint8_t>> solutions;

    // Phase 1: Generate the initial hash table.
    // Each entry is (hash_value, [index]).
    std::vector<TableEntry> table;
    table.reserve(num_initial);

    for (size_t i = 0; i < num_initial; ++i) {
        TableEntry entry;
        entry.hash = generate_hash(params, input,
            static_cast<uint32_t>(i));
        entry.indices.push_back(static_cast<uint32_t>(i));
        table.push_back(std::move(entry));
    }

    // Phase 2: Wagner rounds.
    // In each round, find pairs whose hashes collide on the
    // current collision window, XOR them, and proceed.
    for (unsigned round = 0; round < params.k; ++round) {
        // Group entries by their collision bucket key.
        std::unordered_map<uint64_t, std::vector<size_t>>
            buckets;
        buckets.reserve(table.size());

        for (size_t i = 0; i < table.size(); ++i) {
            uint64_t key = bucket_key(
                table[i].hash, round, params);
            buckets[key].push_back(i);
        }

        std::vector<TableEntry> next_table;

        for (auto& [key, bucket] : buckets) {
            // For each pair in this bucket, create a new entry.
            for (size_t a = 0; a < bucket.size(); ++a) {
                for (size_t b = a + 1; b < bucket.size(); ++b) {
                    const auto& entry_a = table[bucket[a]];
                    const auto& entry_b = table[bucket[b]];

                    // Ordering constraint: the minimum index in
                    // entry_a's set must be less than the minimum
                    // in entry_b's set.
                    uint32_t min_a = *std::min_element(
                        entry_a.indices.begin(),
                        entry_a.indices.end());
                    uint32_t min_b = *std::min_element(
                        entry_b.indices.begin(),
                        entry_b.indices.end());

                    const TableEntry* left;
                    const TableEntry* right;
                    if (min_a < min_b) {
                        left = &entry_a;
                        right = &entry_b;
                    } else if (min_b < min_a) {
                        left = &entry_b;
                        right = &entry_a;
                    } else {
                        // Same minimum index -- skip (would
                        // violate distinctness).
                        continue;
                    }

                    // Check that index sets don't overlap.
                    bool overlap = false;
                    for (uint32_t idx_l : left->indices) {
                        for (uint32_t idx_r : right->indices) {
                            if (idx_l == idx_r) {
                                overlap = true;
                                break;
                            }
                        }
                        if (overlap) break;
                    }
                    if (overlap) continue;

                    // XOR the hashes.
                    TableEntry new_entry;
                    xor_bytes(new_entry.hash,
                        left->hash, right->hash);

                    // Verify collision: the leading
                    // (round+1)*bits_per_round bits must be zero.
                    if (!has_leading_zero_bits(new_entry.hash,
                            (round + 1) * bits_per_round)) {
                        continue;
                    }

                    // Merge indices (left then right).
                    new_entry.indices.reserve(
                        left->indices.size() +
                        right->indices.size());
                    new_entry.indices.insert(
                        new_entry.indices.end(),
                        left->indices.begin(),
                        left->indices.end());
                    new_entry.indices.insert(
                        new_entry.indices.end(),
                        right->indices.begin(),
                        right->indices.end());

                    // On the final round, check for a complete
                    // solution (all bits zero).
                    if (round == params.k - 1) {
                        if (is_all_zero(new_entry.hash)) {
                            auto packed = pack_indices(
                                new_entry.indices, bit_len);
                            solutions.push_back(
                                std::move(packed));
                            if (solutions.size() >=
                                    max_solutions) {
                                return solutions;
                            }
                        }
                    } else {
                        next_table.push_back(
                            std::move(new_entry));
                    }
                }
            }
        }

        table = std::move(next_table);

        // If the table is empty after a round, no solutions
        // can be found.
        if (table.empty() && round < params.k - 1) {
            break;
        }
    }

    return solutions;
}

}  // namespace crypto
