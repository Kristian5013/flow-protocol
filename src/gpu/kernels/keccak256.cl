// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// =========================================================================
// keccak256.cl -- Keccak-f[1600] permutation for OpenCL
// =========================================================================
//
// Scalar-variable implementation: all 25 state lanes live in individual
// registers (s00..s44) to prevent dead-store elimination by the compiler.
// All 24 rounds are fully unrolled with compile-time round constants.
//
// Naming: sXY  =>  state[X + 5*Y]   (X = column, Y = row)
// =========================================================================

#ifndef KECCAK256_CL
#define KECCAK256_CL

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// -------------------------------------------------------------------------
// One round of Keccak-f[1600]: Theta -> Rho -> Pi -> Chi -> Iota
// Operates on 25 scalar variables s00..s44 in the enclosing scope.
// -------------------------------------------------------------------------

#define KECCAK_ROUND(rc) do {                                              \
    /* Theta */                                                            \
    ulong c0 = s00 ^ s01 ^ s02 ^ s03 ^ s04;                              \
    ulong c1 = s10 ^ s11 ^ s12 ^ s13 ^ s14;                              \
    ulong c2 = s20 ^ s21 ^ s22 ^ s23 ^ s24;                              \
    ulong c3 = s30 ^ s31 ^ s32 ^ s33 ^ s34;                              \
    ulong c4 = s40 ^ s41 ^ s42 ^ s43 ^ s44;                              \
    ulong d0 = c4 ^ ROL64(c1, 1);                                         \
    ulong d1 = c0 ^ ROL64(c2, 1);                                         \
    ulong d2 = c1 ^ ROL64(c3, 1);                                         \
    ulong d3 = c2 ^ ROL64(c4, 1);                                         \
    ulong d4 = c3 ^ ROL64(c0, 1);                                         \
    s00 ^= d0; s01 ^= d0; s02 ^= d0; s03 ^= d0; s04 ^= d0;              \
    s10 ^= d1; s11 ^= d1; s12 ^= d1; s13 ^= d1; s14 ^= d1;              \
    s20 ^= d2; s21 ^= d2; s22 ^= d2; s23 ^= d2; s24 ^= d2;              \
    s30 ^= d3; s31 ^= d3; s32 ^= d3; s33 ^= d3; s34 ^= d3;              \
    s40 ^= d4; s41 ^= d4; s42 ^= d4; s43 ^= d4; s44 ^= d4;              \
    /* Rho */                                                              \
    s10 = ROL64(s10,  1); s20 = ROL64(s20, 62);                           \
    s30 = ROL64(s30, 28); s40 = ROL64(s40, 27);                           \
    s01 = ROL64(s01, 36); s11 = ROL64(s11, 44);                           \
    s21 = ROL64(s21,  6); s31 = ROL64(s31, 55);                           \
    s41 = ROL64(s41, 20); s02 = ROL64(s02,  3);                           \
    s12 = ROL64(s12, 10); s22 = ROL64(s22, 43);                           \
    s32 = ROL64(s32, 25); s42 = ROL64(s42, 39);                           \
    s03 = ROL64(s03, 41); s13 = ROL64(s13, 45);                           \
    s23 = ROL64(s23, 15); s33 = ROL64(s33, 21);                           \
    s43 = ROL64(s43,  8); s04 = ROL64(s04, 18);                           \
    s14 = ROL64(s14,  2); s24 = ROL64(s24, 61);                           \
    s34 = ROL64(s34, 56); s44 = ROL64(s44, 14);                           \
    /* Pi */                                                               \
    { ulong p00=s00, p10=s10, p20=s20, p30=s30, p40=s40,                  \
            p01=s01, p11=s11, p21=s21, p31=s31, p41=s41,                  \
            p02=s02, p12=s12, p22=s22, p32=s32, p42=s42,                  \
            p03=s03, p13=s13, p23=s23, p33=s33, p43=s43,                  \
            p04=s04, p14=s14, p24=s24, p34=s34, p44=s44;                  \
      s00=p00; s10=p11; s20=p22; s30=p33; s40=p44;                        \
      s01=p30; s11=p41; s21=p02; s31=p13; s41=p24;                        \
      s02=p10; s12=p21; s22=p32; s32=p43; s42=p04;                        \
      s03=p40; s13=p01; s23=p12; s33=p23; s43=p34;                        \
      s04=p20; s14=p31; s24=p42; s34=p03; s44=p14;                        \
    }                                                                      \
    /* Chi */                                                              \
    { ulong a0=s00,a1=s10,a2=s20,a3=s30,a4=s40;                           \
      s00=a0^(~a1&a2); s10=a1^(~a2&a3); s20=a2^(~a3&a4);                 \
      s30=a3^(~a4&a0); s40=a4^(~a0&a1); }                                 \
    { ulong a0=s01,a1=s11,a2=s21,a3=s31,a4=s41;                           \
      s01=a0^(~a1&a2); s11=a1^(~a2&a3); s21=a2^(~a3&a4);                 \
      s31=a3^(~a4&a0); s41=a4^(~a0&a1); }                                 \
    { ulong a0=s02,a1=s12,a2=s22,a3=s32,a4=s42;                           \
      s02=a0^(~a1&a2); s12=a1^(~a2&a3); s22=a2^(~a3&a4);                 \
      s32=a3^(~a4&a0); s42=a4^(~a0&a1); }                                 \
    { ulong a0=s03,a1=s13,a2=s23,a3=s33,a4=s43;                           \
      s03=a0^(~a1&a2); s13=a1^(~a2&a3); s23=a2^(~a3&a4);                 \
      s33=a3^(~a4&a0); s43=a4^(~a0&a1); }                                 \
    { ulong a0=s04,a1=s14,a2=s24,a3=s34,a4=s44;                           \
      s04=a0^(~a1&a2); s14=a1^(~a2&a3); s24=a2^(~a3&a4);                 \
      s34=a3^(~a4&a0); s44=a4^(~a0&a1); }                                 \
    /* Iota */                                                             \
    s00 ^= (rc);                                                           \
} while(0)

// -------------------------------------------------------------------------
// Full 24-round Keccak-f[1600] permutation.
// Fully unrolled with compile-time constants for maximum throughput.
// Each round constant is an immediate operand — no memory loads from RC[].
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
