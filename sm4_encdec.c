//  sm4_encdec.c
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  SM4 (Chinese Encryption Standard) Encryption and Decryption

#include "sm4_encdec.h"
#include "enc1s.h"
#include "endian.h"

//  encrypt or decrypt a block, depending on round key ordering

void sm4_encdec(uint8_t out[16], const uint8_t in[16],
                 const uint32_t rk[SM4_RK_WORDS])
{
    uint32_t x0, x1, x2, x3, t, u;
    const uint32_t *kp = &rk[SM4_RK_WORDS];

    x0 = GETU32_LE(in);                     //  little endian (native)
    x1 = GETU32_LE(in +  4);
    x2 = GETU32_LE(in +  8);
    x3 = GETU32_LE(in + 12);

    do {

        u   =   x2 ^ x3;                    //  10 XORs total per round

        t   =   rk[0];                      //  subkeys can be inline
        t   ^=  u;
        t   ^=  x1;
        x0  =   enc4s(t, x0, SM4_FN_ENC);   //  4 x enc4s (or 16 x enc1s) per R

        t   =   rk[1];
        t   ^=  u;
        t   ^=  x0;
        x1  =   enc4s(t, x1, SM4_FN_ENC);

        u   =   x0 ^ x1;

        t   =   rk[2];
        t   ^=  u;
        t   ^=  x3;
        x2  =   enc4s(t, x2, SM4_FN_ENC);

        t   =   rk[3];
        t   ^=  u;
        t   ^=  x2;
        x3  =   enc4s(t, x3, SM4_FN_ENC);

        rk += 4;                            //  unroll to taste

    } while (rk != kp);

    PUTU32_LE(out,      x3);
    PUTU32_LE(out +  4, x2);
    PUTU32_LE(out +  8, x1);
    PUTU32_LE(out + 12, x0);
}

//  set key for encryption

void sm4_enc_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
    const uint32_t *kp = &rk[SM4_RK_WORDS];
    uint32_t x0, x1, x2, x3;
    uint32_t t, u, ck;

    x0 = GETU32_LE(key);                    //  fetch key words
    x1 = GETU32_LE(key + 4);
    x2 = GETU32_LE(key + 8);
    x3 = GETU32_LE(key + 12);

    x0 ^= 0xC6BAB1A3;                       //  "FK" constants, little-endian
    x1 ^= 0x5033AA56;                       //  (note: these seem pointless)
    x2 ^= 0x97917D67;
    x3 ^= 0xDC2270B2;

    ck = 0x140E0600;                        //  0x150E0700 with LSBs masked

    do {
/*
    "CK" Discussion:

    The SM4 "CK" round constants are a sequence of bytes 7*i (mod 256) with
    i = 0..127, interpreted as 32-bit words. Often these words are stored in
    a constant table. However many ISAs have a "SIMD" addition that adds 4 or
    more bytes in parallel, which is faster than a table look-up. Even some
    low-ended embedded targets such as Cortex M4 (Armv7E-M/DSP) support this
    (SADD8) and its introduction as a RISC-V extension should be considered.
    Meanwhile, we can perfom the same function with three simple arithmetic
    ops which is likely to still be faster than fetching from a table and
    (with the address arithmatic). This implementation is certainly smaller.
*/
        t   =   ck ^ 0x01000100;            //  these constants in registers
        ck  +=  0x1C1C1C1C;                 //  if we have "SADD8", then
        ck  &=  0xFEFEFEFE;                 //  -> 4 x "SADD8" per round.

        u   =   x2 ^ x3;                    //  10 XORs per round
        t   =   t  ^ u;
        t   =   t  ^ x1;
        x0  =   enc4s(t, x0, SM4_FN_KEY);   //  4 x ENC4S (or 16 x ENC1S)
        rk[0] = x0;                         //  four stores per round

        t   =   ck ^ 0x01000100;
        ck  +=  0x1C1C1C1C;
        ck  &=  0xFEFEFEFE;

        t   =   t  ^ u;
        t   =   t  ^ x0;
        x1  =   enc4s(t, x1, SM4_FN_KEY);
        rk[1] = x1;

        t   =   ck ^ 0x01000100;
        ck  +=  0x1C1C1C1C;
        ck  &=  0xFEFEFEFE;

        u   =   x0 ^ x1;
        t   ^=  u;
        t   ^=  x3;
        x2  =   enc4s(t, x2, SM4_FN_KEY);
        rk[2] = x2;

        t   =   ck ^ 0x01000100;
        ck  +=  0x1C1C1C1C;
        ck  &=  0xFEFEFEFE;

        t   ^=  u;
        t   ^=  x2;
        x3  =   enc4s(t, x3, SM4_FN_KEY);
        rk[3] = x3;

        rk  +=  4;

    } while (rk != kp);
}

//  set key for decryption

void sm4_dec_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
    uint32_t t;
    int i, j;

    sm4_enc_key(rk, key);                   //  create encryption keys

    //  simply reverse the order of the key words
    for (i = 0, j = SM4_RK_WORDS - 1; i < j; i++, j--) {
        t = rk[i];
        rk[i] = rk[j];
        rk[j] = t;
    }
}

