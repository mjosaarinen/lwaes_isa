//  aes_enc.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "Running pseudocode" for full AES-128/192/256 encryption.

#include "enc1s.h"
#include "aes_enc.h"
#include "endian.h"

//  round constants -- just iterations of the xtime() LFSR

static const uint8_t aes_rcon[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

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

    while (1) {                             //  double round

        u0 = rk[4];                         //  fetch odd subkey
        u1 = rk[5];
        u2 = rk[6];
        u3 = rk[7];

        u0 = enc1s(t0, u0, AES_FN_ENC);     //  AES round, 16 instructions
        u0 = enc1s(t1, u0, AES_FN_ENC | 1);
        u0 = enc1s(t2, u0, AES_FN_ENC | 2);
        u0 = enc1s(t3, u0, AES_FN_ENC | 3);

        u1 = enc1s(t1, u1, AES_FN_ENC);
        u1 = enc1s(t2, u1, AES_FN_ENC | 1);
        u1 = enc1s(t3, u1, AES_FN_ENC | 2);
        u1 = enc1s(t0, u1, AES_FN_ENC | 3);

        u2 = enc1s(t2, u2, AES_FN_ENC);
        u2 = enc1s(t3, u2, AES_FN_ENC | 1);
        u2 = enc1s(t0, u2, AES_FN_ENC | 2);
        u2 = enc1s(t1, u2, AES_FN_ENC | 3);

        u3 = enc1s(t3, u3, AES_FN_ENC);
        u3 = enc1s(t0, u3, AES_FN_ENC | 1);
        u3 = enc1s(t1, u3, AES_FN_ENC | 2);
        u3 = enc1s(t2, u3, AES_FN_ENC | 3);

        t0 = rk[8];                         //  fetch even subkey
        t1 = rk[9];
        t2 = rk[10];
        t3 = rk[11];

        rk += 8;                            //  step key pointer
        if (rk == kp)                       //  final round ?
            break;

        t0 = enc1s(u0, t0, AES_FN_ENC);     //  final encrypt round, 16 ins.
        t0 = enc1s(u1, t0, AES_FN_ENC | 1);
        t0 = enc1s(u2, t0, AES_FN_ENC | 2);
        t0 = enc1s(u3, t0, AES_FN_ENC | 3);

        t1 = enc1s(u1, t1, AES_FN_ENC);
        t1 = enc1s(u2, t1, AES_FN_ENC | 1);
        t1 = enc1s(u3, t1, AES_FN_ENC | 2);
        t1 = enc1s(u0, t1, AES_FN_ENC | 3);

        t2 = enc1s(u2, t2, AES_FN_ENC);
        t2 = enc1s(u3, t2, AES_FN_ENC | 1);
        t2 = enc1s(u0, t2, AES_FN_ENC | 2);
        t2 = enc1s(u1, t2, AES_FN_ENC | 3);

        t3 = enc1s(u3, t3, AES_FN_ENC);
        t3 = enc1s(u0, t3, AES_FN_ENC | 1);
        t3 = enc1s(u1, t3, AES_FN_ENC | 2);
        t3 = enc1s(u2, t3, AES_FN_ENC | 3);
    }

    t0 = enc1s(u0, t0, AES_FN_FWD);         //  final round is different
    t0 = enc1s(u1, t0, AES_FN_FWD | 1);
    t0 = enc1s(u2, t0, AES_FN_FWD | 2);
    t0 = enc1s(u3, t0, AES_FN_FWD | 3);

    t1 = enc1s(u1, t1, AES_FN_FWD);
    t1 = enc1s(u2, t1, AES_FN_FWD | 1);
    t1 = enc1s(u3, t1, AES_FN_FWD | 2);
    t1 = enc1s(u0, t1, AES_FN_FWD | 3);

    t2 = enc1s(u2, t2, AES_FN_FWD);
    t2 = enc1s(u3, t2, AES_FN_FWD | 1);
    t2 = enc1s(u0, t2, AES_FN_FWD | 2);
    t2 = enc1s(u1, t2, AES_FN_FWD | 3);

    t3 = enc1s(u3, t3, AES_FN_FWD);
    t3 = enc1s(u0, t3, AES_FN_FWD | 1);
    t3 = enc1s(u1, t3, AES_FN_FWD | 2);
    t3 = enc1s(u2, t3, AES_FN_FWD | 3);

    PUTU32_LE(ct, t0);                      //  write ciphertext block
    PUTU32_LE(ct + 4, t1);
    PUTU32_LE(ct + 8, t2);
    PUTU32_LE(ct + 12, t3);
}

//  ( Note: RISC-V has enough registers to compute subkeys on the fly. )

//  Key schedule for AES-128 Encryption.

void aes128_enc_key(uint32_t rk[44], const uint8_t key[16])
{
    uint32_t t0, t1, t2, t3, tr;            //  subkey registers
    const uint32_t *rke = &rk[44 - 4];      //  end pointer
    const uint8_t *rc = aes_rcon;           //  round constants

    t0 = GETU32_LE(key);                    //  load secret key
    t1 = GETU32_LE(key + 4);
    t2 = GETU32_LE(key + 8);
    t3 = GETU32_LE(key + 12);

    while (1) {

        rk[0] = t0;                         //  store subkey
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;

        if (rk == rke)                      //  end condition
            return;
        rk += 4;                            //  step pointer by one subkey

        t0 ^= (uint32_t) *rc++;             //  round constant
        tr = ROTL32(t3, 24);                //  rotate 8 bits (little endian!)
        t0 = enc4s(tr, t0, AES_FN_FWD);     //  SubWord()
        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
    }
}

//  Key schedule for AES-192 encryption.

void aes192_enc_key(uint32_t rk[52], const uint8_t key[24])
{
    uint32_t t0, t1, t2, t3, t4, t5, tr;    //  subkey registers
    const uint32_t *rke = &rk[52 - 4];      //  end pointer
    const uint8_t *rc = aes_rcon;           //  round constants

    t0 = GETU32_LE(key);                    //  load secret key
    t1 = GETU32_LE(key + 4);
    t2 = GETU32_LE(key + 8);
    t3 = GETU32_LE(key + 12);
    t4 = GETU32_LE(key + 16);
    t5 = GETU32_LE(key + 20);

    while (1) {

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
        tr = ROTL32(t5, 24);                //  rotate 8 bits (little endian!)
        t0 = enc4s(tr, t0, AES_FN_FWD);     //  SubWord()

        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;
        t4 ^= t3;
        t5 ^= t4;
    }
}

//  Key schedule for AES-256 encryption.

void aes256_enc_key(uint32_t rk[60], const uint8_t key[32])
{
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, tr; // subkey registers
    const uint32_t *rke = &rk[60 - 4];      //  end pointer
    const uint8_t *rc = aes_rcon;           //  round constants

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

    while (1) {

        rk[4] = t4;                         //  store odd subkey
        rk[5] = t5;
        rk[6] = t6;
        rk[7] = t7;
        rk += 8;                            //  step pointer by 2 subkeys

        t0 ^= (uint32_t) *rc++;             //  round constant
        tr = ROTL32(t7, 24);                //  rotate 8 bits (little endian!)
        t0 = enc4s(tr, t0, AES_FN_FWD);     //  SubWord()
        t1 ^= t0;
        t2 ^= t1;
        t3 ^= t2;

        rk[0] = t0;                         //  store even subkey
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t3;
        if (rk == rke)                      //  end condition
            return;

        t4 = enc4s(t3, t4, AES_FN_FWD);     //  SubWord() - NO rotation
        t5 ^= t4;
        t6 ^= t5;
        t7 ^= t6;
    }
}
