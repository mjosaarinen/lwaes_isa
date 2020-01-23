//  aes_enc1s.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "running pseudocode" for single-sbox lightweight aes encryption instruction

#include "aesenc.h"

//  round constants -- just iterations of the mulx() LFSR

static const uint8_t rcon[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

//  AES Forward S-Box

static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16
};

//  === THIS IS THE LIGHTWEIGHT INSTRUCTION FOR AES ENCRYPTION ===

//  One S-Box lookup and partial MixColumn(), 7-bit fn (5 bits used)

uint32_t aes_enc1s(uint32_t rs1, uint32_t rs2, int fn)
{
    uint32_t fra, frb, t, u, v, x, x2;

    fra = 8 * (fn & 3);                     //  [1:0] byte selector in
    frb = 8 * ((fn >> 3) & 3);              //  [4:3] byte rotation out

    t = (rs1 >> fra) & 0xFF;                //  get byte
    x = sbox[t];                            //  s-box lookup (8-bit)

    //  Multiply by "x" in AES's GF(256) - LFSR style
    x2 =  (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00 );

    if (fn & 0100) {                        //  Bit 6 selects MDS
        //  Forward MDS ("MixColumn")
        u = ((x ^ x2)   << 24) |            //  0x03
            (x          << 16) |            //  0x01
            (x          <<  8) |            //  0x01
            x2;                             //  0x02

    } else {
        u = x;                              //  Last round and key schedule
    }

    if (frb != 0) {                         //  rotate output left
        v = (u << frb) | (u >> (32 - frb));
    } else {
        v = u;
    }

    return v ^ rs2;                         //  XOR with rs2 and write out
}

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

void aes_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
                    const uint32_t rk[], int nr)
{
    uint32_t t0, t1, t2, t3;                //  even round state registers
    uint32_t u0, u1, u2, u3;                //  odd round state registers
    const uint32_t *kp = &rk[4 * nr];       //  key pointer as loop condition

    t0 = rk[0];                             //  fetch even subkey
    t1 = rk[1];
    t2 = rk[2];
    t3 = rk[3];

    t0 ^= GETU32_LE(pt);                    //  xor with plaintext block
    t1 ^= GETU32_LE(pt + 4);
    t2 ^= GETU32_LE(pt + 8);
    t3 ^= GETU32_LE(pt + 12);

    for (;;) {                              //  double round

        u0 = rk[4];                         //  fetch odd subkey
        u1 = rk[5];
        u2 = rk[6];
        u3 = rk[7];

        u0 = aes_enc1s(t0, u0, 0100);       //  AES round, 16 instructions
        u0 = aes_enc1s(t1, u0, 0111);
        u0 = aes_enc1s(t2, u0, 0122);
        u0 = aes_enc1s(t3, u0, 0133);

        u1 = aes_enc1s(t1, u1, 0100);
        u1 = aes_enc1s(t2, u1, 0111);
        u1 = aes_enc1s(t3, u1, 0122);
        u1 = aes_enc1s(t0, u1, 0133);

        u2 = aes_enc1s(t2, u2, 0100);
        u2 = aes_enc1s(t3, u2, 0111);
        u2 = aes_enc1s(t0, u2, 0122);
        u2 = aes_enc1s(t1, u2, 0133);

        u3 = aes_enc1s(t3, u3, 0100);
        u3 = aes_enc1s(t0, u3, 0111);
        u3 = aes_enc1s(t1, u3, 0122);
        u3 = aes_enc1s(t2, u3, 0133);

        t0 = rk[8];                         //  fetch even subkey
        t1 = rk[9];
        t2 = rk[10];
        t3 = rk[11];

        rk += 8;                            //  step key pointer
        if (rk == kp)                       //  final round ?
            break;

        t0 = aes_enc1s(u0, t0, 0100);       //  AES round, 16 instructions
        t0 = aes_enc1s(u1, t0, 0111);
        t0 = aes_enc1s(u2, t0, 0122);
        t0 = aes_enc1s(u3, t0, 0133);

        t1 = aes_enc1s(u1, t1, 0100);
        t1 = aes_enc1s(u2, t1, 0111);
        t1 = aes_enc1s(u3, t1, 0122);
        t1 = aes_enc1s(u0, t1, 0133);

        t2 = aes_enc1s(u2, t2, 0100);
        t2 = aes_enc1s(u3, t2, 0111);
        t2 = aes_enc1s(u0, t2, 0122);
        t2 = aes_enc1s(u1, t2, 0133);

        t3 = aes_enc1s(u3, t3, 0100);
        t3 = aes_enc1s(u0, t3, 0111);
        t3 = aes_enc1s(u1, t3, 0122);
        t3 = aes_enc1s(u2, t3, 0133);
    }

    t0 = aes_enc1s(u0, t0, 0000);           //  final round is different
    t0 = aes_enc1s(u1, t0, 0011);
    t0 = aes_enc1s(u2, t0, 0022);
    t0 = aes_enc1s(u3, t0, 0033);

    t1 = aes_enc1s(u1, t1, 0000);
    t1 = aes_enc1s(u2, t1, 0011);
    t1 = aes_enc1s(u3, t1, 0022);
    t1 = aes_enc1s(u0, t1, 0033);

    t2 = aes_enc1s(u2, t2, 0000);
    t2 = aes_enc1s(u3, t2, 0011);
    t2 = aes_enc1s(u0, t2, 0022);
    t2 = aes_enc1s(u1, t2, 0033);

    t3 = aes_enc1s(u3, t3, 0000);
    t3 = aes_enc1s(u0, t3, 0011);
    t3 = aes_enc1s(u1, t3, 0022);
    t3 = aes_enc1s(u2, t3, 0033);

    PUTU32_LE(ct, t0);                      //  write ciphertext block
    PUTU32_LE(ct + 4, t1);
    PUTU32_LE(ct + 8, t2);
    PUTU32_LE(ct + 12, t3);
}

//  ( Note: RISC-V has enough registers to compute subkeys on the fly. )

//  Key sechedule for AES128 Encryption.

void aes128_enc_key(uint32_t rk[44], const uint8_t key[16])
{
    uint32_t t0, t1, t2, t3;                //  subkey registers
    const uint32_t *rke = &rk[44 - 4];      //  end pointer
    const uint8_t *rc = rcon;               //  round constants

    t0 = GETU32_LE(key);                    //  load secret key
    t1 = GETU32_LE(key + 4);
    t2 = GETU32_LE(key + 8);
    t3 = GETU32_LE(key + 12);

    for (;;) {

        rk[0] = t0;                         //  store subkey
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;

        if (rk == rke)                      //  end condition
            return;
        rk += 4;                            //  step pointer by one subkey

        t0 ^= (uint32_t) *rc++;             //  round constant
        t0 = aes_enc1s(t3, t0, 0001);       //  SubWord() and rotation
        t0 = aes_enc1s(t3, t0, 0012);
        t0 = aes_enc1s(t3, t0, 0023);
        t0 = aes_enc1s(t3, t0, 0030);
        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
    }
}


//  Key schedule for AES192 Encryption

void aes192_enc_key(uint32_t rk[52], const uint8_t key[24])
{
    uint32_t t0, t1, t2, t3, t4, t5;        //  subkey registers
    const uint32_t *rke = &rk[52 - 4];      //  end pointer
    const uint8_t *rc = rcon;               //  round constants

    t0 = GETU32_LE(key);                    //  load secret key
    t1 = GETU32_LE(key + 4);
    t2 = GETU32_LE(key + 8);
    t3 = GETU32_LE(key + 12);
    t4 = GETU32_LE(key + 16);
    t5 = GETU32_LE(key + 20);

    for (;;) {

        rk[0] = t0;                         //  store subkey (or part)
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;
        if (rk == rke)                      //  end condition
            return;
        rk[4] = t4;
        rk[5] = t5;
        rk += 6;                            //  step pointer by 1.5 subkeys

        t0 ^= (uint32_t) *rc++;             //  round constant
        t0 = aes_enc1s(t5, t0, 0001);       //  SubWord() and rotation
        t0 = aes_enc1s(t5, t0, 0012);
        t0 = aes_enc1s(t5, t0, 0023);
        t0 = aes_enc1s(t5, t0, 0030);
        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
        t4 ^= t3;
        t5 ^= t4;
    }
}

//  Key schedule for AES256 Encryption

void aes256_enc_key(uint32_t rk[60], const uint8_t key[32])
{
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7; // subkey registers
    const uint32_t *rke = &rk[60 - 4];      //  end pointer
    const uint8_t *rc = rcon;               //  round constants

    t0 = GETU32_LE(key);
    t1 = GETU32_LE(key + 4);
    t2 = GETU32_LE(key + 8);
    t3 = GETU32_LE(key + 12);
    t4 = GETU32_LE(key + 16);
    t5 = GETU32_LE(key + 20);
    t6 = GETU32_LE(key + 24);
    t7 = GETU32_LE(key + 28);

    rk[0] = t0;                             //  store first subkey
    rk[1] = t1;
    rk[2] = t2;
    rk[3] = t3;

    for (;;) {

        rk[4] = t4;                         //  store odd subkey
        rk[5] = t5;
        rk[6] = t6;
        rk[7] = t7;
        rk += 8;                            //  step pointer by 2 subkeys

        t0 ^= (uint32_t) *rc++;             //  round constant
        t0 = aes_enc1s(t7, t0, 0001);       //  SubWord() and rotation
        t0 = aes_enc1s(t7, t0, 0012);
        t0 = aes_enc1s(t7, t0, 0023);
        t0 = aes_enc1s(t7, t0, 0030);
        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;

        rk[0] = t0;                         //  store even subkey
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;
        if (rk == rke)                      //  end condition
            return;

        t4 = aes_enc1s(t3, t4, 0000);       //  SubWord() - NO rotation
        t4 = aes_enc1s(t3, t4, 0011);
        t4 = aes_enc1s(t3, t4, 0022);
        t4 = aes_enc1s(t3, t4, 0033);
        t5 ^= t4;
        t6 ^= t5;
        t7 ^= t6;
    }
}
