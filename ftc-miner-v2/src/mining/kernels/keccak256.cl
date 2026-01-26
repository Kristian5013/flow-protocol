/**
 * Keccak-256 OpenCL Kernel for FTC Mining
 * EXACT COPY of node's Keccak implementation for compatibility
 */

#define KECCAK_ROUNDS 24

// Round constants
__constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
    0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
    0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

// Rotation offsets - SAME as node
__constant int ROTATIONS[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

// Pi permutation indices - SAME as node
__constant int PI[25] = {
     0, 6, 12, 18, 24,
     3, 9, 10, 16, 22,
     1, 7, 13, 19, 20,
     4, 5, 11, 17, 23,
     2, 8, 14, 15, 21
};

inline ulong rotl64(ulong x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] permutation - EXACT COPY from node
void keccak_f1600(ulong* state) {
    ulong C[5], D[5], temp[25];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta step
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^
                   state[x + 15] ^ state[x + 20];
        }

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }

        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // Rho and Pi steps combined - SAME as node
        for (int i = 0; i < 25; i++) {
            temp[PI[i]] = rotl64(state[i], ROTATIONS[i]);
        }

        // Chi step
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int i = y * 5 + x;
                state[i] = temp[i] ^ ((~temp[y * 5 + (x + 1) % 5]) &
                                        temp[y * 5 + (x + 2) % 5]);
            }
        }

        // Iota step
        state[0] ^= RC[round];
    }
}

// Keccak-256 hash function for 80-byte header
void keccak256_80(const uchar* input, ulong nonce, uchar* output) {
    ulong state[25];

    // Initialize state to zero
    for (int i = 0; i < 25; i++) {
        state[i] = 0;
    }

    // Absorb first 72 bytes (9 ulongs)
    for (int i = 0; i < 9; i++) {
        ulong val = 0;
        for (int j = 0; j < 8; j++) {
            val |= ((ulong)input[i * 8 + j]) << (j * 8);
        }
        state[i] ^= val;
    }

    // Absorb last 8 bytes: bytes 72-75 (bits field) + nonce
    ulong last_block = 0;
    for (int j = 0; j < 4; j++) {
        last_block |= ((ulong)input[72 + j]) << (j * 8);
    }
    last_block |= (nonce & 0xFFFFFFFF) << 32;
    state[9] ^= last_block;

    // Padding: 0x01 after message, 0x80 at end of rate
    state[10] ^= 0x01UL;
    state[16] ^= 0x8000000000000000UL;

    // Permute
    keccak_f1600(state);

    // Squeeze 32 bytes output
    for (int i = 0; i < 4; i++) {
        ulong val = state[i];
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = (uchar)(val >> (j * 8));
        }
    }
}

// Compare hash with target (returns 1 if hash <= target)
// BIG-ENDIAN comparison (byte 0 = MSB) - same as node's Keccak256::compare
int compare_hash(const uchar* hash, __global const uchar* target) {
    for (int i = 0; i < 32; i++) {
        if (hash[i] < target[i]) return 1;  // hash < target = valid
        if (hash[i] > target[i]) return 0;  // hash > target = invalid
    }
    return 1;  // hash == target = valid
}

// Main mining kernel
__kernel void mine(
    __global const uchar* header,
    __global const uchar* target,
    __global ulong* nonce_base,
    __global ulong* result_nonce,
    __global int* result_found,
    const ulong nonce_count
) {
    uint gid = get_global_id(0);

    if (*result_found) return;

    uchar local_header[80];
    for (int i = 0; i < 80; i++) {
        local_header[i] = header[i];
    }

    ulong nonce = *nonce_base + (ulong)gid * nonce_count;
    uchar hash[32];

    for (ulong i = 0; i < nonce_count; i++) {
        if (*result_found) return;

        keccak256_80(local_header, nonce, hash);

        if (compare_hash(hash, target)) {
            int expected = 0;
            if (atomic_cmpxchg(result_found, expected, 1) == 0) {
                *result_nonce = nonce;
            }
            return;
        }

        nonce++;
    }
}

// Batch mining kernel
__kernel void mine_batch(
    __global const uchar* header,
    __global const uchar* target,
    const ulong nonce_start,
    __global ulong* results,
    __global volatile uint* result_count
) {
    uint gid = get_global_id(0);

    uchar local_header[80];
    for (int i = 0; i < 80; i++) {
        local_header[i] = header[i];
    }

    ulong nonce = nonce_start + gid;
    uchar hash[32];

    keccak256_80(local_header, nonce, hash);

    if (compare_hash(hash, target)) {
        uint idx = atomic_inc(result_count);
        if (idx < 16) {
            results[idx] = nonce;
        }
    }
}
