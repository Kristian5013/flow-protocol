// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// keccak256.cl -- Keccak-f[1600] permutation for OpenCL
// =========================================================================
//
// Optimized scalar-variable implementation for GPU mining.
// All 25 state lanes live in individual registers (s00..s44).
// All 24 rounds are fully unrolled with compile-time round constants.
//
// Optimizations vs naive implementation:
//   - Merged Rho+Pi: rotate and permute in one step (no intermediate copy)
//   - bitselect() Chi: single hardware instruction on AMD (BFI) / NVIDIA (LOP3)
//   - Reduced Theta temps: reuse one d register across all 5 columns
//   - Full unroll: compile-time round constants as immediate operands
//
// Naming: sXY  =>  state[X + 5*Y]   (X = column, Y = row)
// =========================================================================

#ifndef KECCAK256_CL
#define KECCAK256_CL

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// -------------------------------------------------------------------------
// One round of Keccak-f[1600]: Theta -> Rho+Pi -> Chi -> Iota
// -------------------------------------------------------------------------

#define KECCAK_ROUND(rc) do {                                              \
    /* --- Theta --- */                                                    \
    ulong c0 = s00 ^ s01 ^ s02 ^ s03 ^ s04;                              \
    ulong c1 = s10 ^ s11 ^ s12 ^ s13 ^ s14;                              \
    ulong c2 = s20 ^ s21 ^ s22 ^ s23 ^ s24;                              \
    ulong c3 = s30 ^ s31 ^ s32 ^ s33 ^ s34;                              \
    ulong c4 = s40 ^ s41 ^ s42 ^ s43 ^ s44;                              \
    ulong d;                                                               \
    d = c4 ^ ROL64(c1, 1);                                                \
    s00 ^= d; s01 ^= d; s02 ^= d; s03 ^= d; s04 ^= d;                   \
    d = c0 ^ ROL64(c2, 1);                                                \
    s10 ^= d; s11 ^= d; s12 ^= d; s13 ^= d; s14 ^= d;                   \
    d = c1 ^ ROL64(c3, 1);                                                \
    s20 ^= d; s21 ^= d; s22 ^= d; s23 ^= d; s24 ^= d;                   \
    d = c2 ^ ROL64(c4, 1);                                                \
    s30 ^= d; s31 ^= d; s32 ^= d; s33 ^= d; s34 ^= d;                   \
    d = c3 ^ ROL64(c0, 1);                                                \
    s40 ^= d; s41 ^= d; s42 ^= d; s43 ^= d; s44 ^= d;                   \
    /* --- Merged Rho + Pi --- */                                          \
    /* new[x][y] = ROL(old[(x+3y)%5][x], rho[(x+3y)%5][x]) */            \
    ulong t00 = s00;                                                       \
    ulong t10 = ROL64(s11, 44); ulong t20 = ROL64(s22, 43);              \
    ulong t30 = ROL64(s33, 21); ulong t40 = ROL64(s44, 14);              \
    ulong t01 = ROL64(s30, 28); ulong t11 = ROL64(s41, 20);              \
    ulong t21 = ROL64(s02,  3); ulong t31 = ROL64(s13, 45);              \
    ulong t41 = ROL64(s24, 61);                                            \
    ulong t02 = ROL64(s10,  1); ulong t12 = ROL64(s21,  6);              \
    ulong t22 = ROL64(s32, 25); ulong t32 = ROL64(s43,  8);              \
    ulong t42 = ROL64(s04, 18);                                            \
    ulong t03 = ROL64(s40, 27); ulong t13 = ROL64(s01, 36);              \
    ulong t23 = ROL64(s12, 10); ulong t33 = ROL64(s23, 15);              \
    ulong t43 = ROL64(s34, 56);                                            \
    ulong t04 = ROL64(s20, 62); ulong t14 = ROL64(s31, 55);              \
    ulong t24 = ROL64(s42, 39); ulong t34 = ROL64(s03, 41);              \
    ulong t44 = ROL64(s14,  2);                                            \
    /* --- Chi + Iota (directly on Rho+Pi output) --- */                   \
    /* bitselect(a^c, a, b) == a ^ (~b & c) */                             \
    s00 = bitselect(t00 ^ t20, t00, t10) ^ (rc);                          \
    s10 = bitselect(t10 ^ t30, t10, t20);                                  \
    s20 = bitselect(t20 ^ t40, t20, t30);                                  \
    s30 = bitselect(t30 ^ t00, t30, t40);                                  \
    s40 = bitselect(t40 ^ t10, t40, t00);                                  \
    s01 = bitselect(t01 ^ t21, t01, t11);                                  \
    s11 = bitselect(t11 ^ t31, t11, t21);                                  \
    s21 = bitselect(t21 ^ t41, t21, t31);                                  \
    s31 = bitselect(t31 ^ t01, t31, t41);                                  \
    s41 = bitselect(t41 ^ t11, t41, t01);                                  \
    s02 = bitselect(t02 ^ t22, t02, t12);                                  \
    s12 = bitselect(t12 ^ t32, t12, t22);                                  \
    s22 = bitselect(t22 ^ t42, t22, t32);                                  \
    s32 = bitselect(t32 ^ t02, t32, t42);                                  \
    s42 = bitselect(t42 ^ t12, t42, t02);                                  \
    s03 = bitselect(t03 ^ t23, t03, t13);                                  \
    s13 = bitselect(t13 ^ t33, t13, t23);                                  \
    s23 = bitselect(t23 ^ t43, t23, t33);                                  \
    s33 = bitselect(t33 ^ t03, t33, t43);                                  \
    s43 = bitselect(t43 ^ t13, t43, t03);                                  \
    s04 = bitselect(t04 ^ t24, t04, t14);                                  \
    s14 = bitselect(t14 ^ t34, t14, t24);                                  \
    s24 = bitselect(t24 ^ t44, t24, t34);                                  \
    s34 = bitselect(t34 ^ t04, t34, t44);                                  \
    s44 = bitselect(t44 ^ t14, t44, t04);                                  \
} while(0)

// -------------------------------------------------------------------------
// Full 24-round Keccak-f[1600] permutation.
// Fully unrolled with compile-time round constants.
// -------------------------------------------------------------------------

#define KECCAK_F1600() do {                                                \
    KECCAK_ROUND(0x0000000000000001UL);                                    \
    KECCAK_ROUND(0x0000000000008082UL);                                    \
    KECCAK_ROUND(0x800000000000808AUL);                                    \
    KECCAK_ROUND(0x8000000080008000UL);                                    \
    KECCAK_ROUND(0x000000000000808BUL);                                    \
    KECCAK_ROUND(0x0000000080000001UL);                                    \
    KECCAK_ROUND(0x8000000080008081UL);                                    \
    KECCAK_ROUND(0x8000000000008009UL);                                    \
    KECCAK_ROUND(0x000000000000008AUL);                                    \
    KECCAK_ROUND(0x0000000000000088UL);                                    \
    KECCAK_ROUND(0x0000000080008009UL);                                    \
    KECCAK_ROUND(0x000000008000000AUL);                                    \
    KECCAK_ROUND(0x000000008000808BUL);                                    \
    KECCAK_ROUND(0x800000000000008BUL);                                    \
    KECCAK_ROUND(0x8000000000008089UL);                                    \
    KECCAK_ROUND(0x8000000000008003UL);                                    \
    KECCAK_ROUND(0x8000000000008002UL);                                    \
    KECCAK_ROUND(0x8000000000000080UL);                                    \
    KECCAK_ROUND(0x000000000000800AUL);                                    \
    KECCAK_ROUND(0x800000008000000AUL);                                    \
    KECCAK_ROUND(0x8000000080008081UL);                                    \
    KECCAK_ROUND(0x8000000000008080UL);                                    \
    KECCAK_ROUND(0x0000000080000001UL);                                    \
    KECCAK_ROUND(0x8000000080008008UL);                                    \
} while(0)

#endif // KECCAK256_CL
