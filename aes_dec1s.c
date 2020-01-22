//  aes_dec1s.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "running pseudocode" for single-sbox lightweight aes decryption instruction

#include "aesdec.h"

//  AES Inverse S-Box

static const uint8_t isbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D
};

//  Multiply by "x" in AES's GF(256) - LFSR style

static inline uint8_t mulx(uint8_t x)
{
    return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00 );
}

//  === THIS IS THE LIGHTWEIGHT INSTRUCTION FOR AES DECRYPTION ===

//  One S-Box lookup and partial MixColumn(), 7-bit fn (5 bits used)

uint32_t aes_dec1s(uint32_t rs1, uint32_t rs2, int fn)
{
    uint32_t fra, frb, t, u, v, x, x2, x4, x8;

    fra = 8 * (fn & 3);                     //  [1:0] byte selector in
    frb = 8 * ((fn >> 3) & 3);              //  [4:3] byte rotation out

    t = (rs1 >> fra) & 0xFF;                //  get byte
    x = isbox[t];                           //  inverse s-box lookup (8-bit)

    x2 = mulx(x);                           //  "double" it
    x4 = mulx(x2);                          //  "double" it to 4
    x8 = mulx(x4);                          //  "double" it to 8

    //  Reverse MDS ("MixColumn")

    if (fn & 0100) {                        //  Bit 6 selects MDS
        u = ((x ^ x2 ^ x8)  << 24) |        //  0x0B
            ((x ^ x4 ^ x8)  << 16) |        //  0x0D
            ((x ^ x8)       <<  8) |        //  0x09
            (x2 ^ x4 ^ x8);                 //  0x0E
    } else {
        u = x;                              //  Used in the last round
    }

    if (frb != 0) {                         //  rotate output left
        v = (u << frb) | (u >> (32 - frb));
    } else {
        v = u;
    }

    return v ^ rs2;                         //  XOR with rs2 and write out
}

//  Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

void aes_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
                    const uint32_t rk[], int nr)
{
    uint32_t t0, t1, t2, t3;                //  even round state registers
    uint32_t u0, u1, u2, u3;                //  odd round state registers
    const uint32_t *kp = &rk[4 * nr];       //  key pointer

    t0 = kp[0];                             //  fetch last subkey
    t1 = kp[1];
    t2 = kp[2];
    t3 = kp[3];
    kp -= 8;

    t0 ^= GETU32_LE(ct);                    //  xor with ciphertext block
    t1 ^= GETU32_LE(ct + 4);
    t2 ^= GETU32_LE(ct + 8);
    t3 ^= GETU32_LE(ct + 12);

    for (;;) {
        u0 = kp[4];                         //  fetch odd subkey
        u1 = kp[5];
        u2 = kp[6];
        u3 = kp[7];

        u0 = aes_dec1s(t0, u0, 0100);       //  AES decryption round, 16 instr
        u0 = aes_dec1s(t3, u0, 0111);
        u0 = aes_dec1s(t2, u0, 0122);
        u0 = aes_dec1s(t1, u0, 0133);

        u1 = aes_dec1s(t1, u1, 0100);
        u1 = aes_dec1s(t0, u1, 0111);
        u1 = aes_dec1s(t3, u1, 0122);
        u1 = aes_dec1s(t2, u1, 0133);

        u2 = aes_dec1s(t2, u2, 0100);
        u2 = aes_dec1s(t1, u2, 0111);
        u2 = aes_dec1s(t0, u2, 0122);
        u2 = aes_dec1s(t3, u2, 0133);

        u3 = aes_dec1s(t3, u3, 0100);
        u3 = aes_dec1s(t2, u3, 0111);
        u3 = aes_dec1s(t1, u3, 0122);
        u3 = aes_dec1s(t0, u3, 0133);

        t0 = kp[0];                         //  fetch even subkey
        t1 = kp[1];
        t2 = kp[2];
        t3 = kp[3];

        if (kp == rk)                       //  final round
            break;
        kp -= 8;

        t0 = aes_dec1s(u0, t0, 0100);       //  AES decryption round, 16 instr
        t0 = aes_dec1s(u3, t0, 0111);
        t0 = aes_dec1s(u2, t0, 0122);
        t0 = aes_dec1s(u1, t0, 0133);

        t1 = aes_dec1s(u1, t1, 0100);
        t1 = aes_dec1s(u0, t1, 0111);
        t1 = aes_dec1s(u3, t1, 0122);
        t1 = aes_dec1s(u2, t1, 0133);

        t2 = aes_dec1s(u2, t2, 0100);
        t2 = aes_dec1s(u1, t2, 0111);
        t2 = aes_dec1s(u0, t2, 0122);
        t2 = aes_dec1s(u3, t2, 0133);

        t3 = aes_dec1s(u3, t3, 0100);
        t3 = aes_dec1s(u2, t3, 0111);
        t3 = aes_dec1s(u1, t3, 0122);
        t3 = aes_dec1s(u0, t3, 0133);
    }

    t0 = aes_dec1s(u0, t0, 0000);           //  final decryption round
    t0 = aes_dec1s(u3, t0, 0011);
    t0 = aes_dec1s(u2, t0, 0022);
    t0 = aes_dec1s(u1, t0, 0033);

    t1 = aes_dec1s(u1, t1, 0000);
    t1 = aes_dec1s(u0, t1, 0011);
    t1 = aes_dec1s(u3, t1, 0022);
    t1 = aes_dec1s(u2, t1, 0033);

    t2 = aes_dec1s(u2, t2, 0000);
    t2 = aes_dec1s(u1, t2, 0011);
    t2 = aes_dec1s(u0, t2, 0022);
    t2 = aes_dec1s(u3, t2, 0033);

    t3 = aes_dec1s(u3, t3, 0000);
    t3 = aes_dec1s(u2, t3, 0011);
    t3 = aes_dec1s(u1, t3, 0022);
    t3 = aes_dec1s(u0, t3, 0033);

    PUTU32_LE(pt, t0);                      //  write plaintext block
    PUTU32_LE(pt + 4, t1);
    PUTU32_LE(pt + 8, t2);
    PUTU32_LE(pt + 12, t3);
}

//  Helper: apply inverse mixcolumns to a vector
//  If decryption keys are computed in the fly (inverse key schedule), there's
//  no need for the encryption instruction (but you need final subkey).

static void aes_dec_invmc(uint32_t *v, size_t len)
{
    size_t i;
    uint32_t x, y;

    for (i = 0; i < len; i++) {
        x = v[i];
        y = aes_enc1s(x, 0, 0000);          //  SubWord()
        y = aes_enc1s(x, y, 0011);
        y = aes_enc1s(x, y, 0022);
        y = aes_enc1s(x, y, 0033);
        x = aes_dec1s(y, 0, 0100);          //  We just want the MixCol()
        x = aes_dec1s(y, x, 0111);
        x = aes_dec1s(y, x, 0122);
        x = aes_dec1s(y, x, 0133);
        v[i] = x;
    }
}

void aes128_dec_key(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16])
{
    //  create an encryption key and modify middle rounds
    aes128_enc_key(rk, key);
    aes_dec_invmc(rk + 4, AES128_RK_WORDS - 8);
}

void aes192_dec_key(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24])
{
    //  create an encryption key and modify middle rounds
    aes192_enc_key(rk, key);
    aes_dec_invmc(rk + 4, AES192_RK_WORDS - 8);
}

void aes256_dec_key(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32])
{
    //  create an encryption key and modify middle rounds
    aes256_enc_key(rk, key);
    aes_dec_invmc(rk + 4, AES256_RK_WORDS - 8);
}

