//  aes_dec.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Running pseudocode for full AES-128/192/256 decryption.

#include "enc1s.h"
#include "aes_dec.h"
#include "endian.h"

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

    while (1) {
        u0 = kp[4];                         //  fetch odd subkey
        u1 = kp[5];
        u2 = kp[6];
        u3 = kp[7];

        u0 = enc1s(u0, t0, AES_FN_DEC);     //  AES decryption round, 16 instr
        u0 = enc1s(u0, t3, AES_FN_DEC | 1);
        u0 = enc1s(u0, t2, AES_FN_DEC | 2);
        u0 = enc1s(u0, t1, AES_FN_DEC | 3);

        u1 = enc1s(u1, t1, AES_FN_DEC);
        u1 = enc1s(u1, t0, AES_FN_DEC | 1);
        u1 = enc1s(u1, t3, AES_FN_DEC | 2);
        u1 = enc1s(u1, t2, AES_FN_DEC | 3);

        u2 = enc1s(u2, t2, AES_FN_DEC);
        u2 = enc1s(u2, t1, AES_FN_DEC | 1);
        u2 = enc1s(u2, t0, AES_FN_DEC | 2);
        u2 = enc1s(u2, t3, AES_FN_DEC | 3);

        u3 = enc1s(u3, t3, AES_FN_DEC);
        u3 = enc1s(u3, t2, AES_FN_DEC | 1);
        u3 = enc1s(u3, t1, AES_FN_DEC | 2);
        u3 = enc1s(u3, t0, AES_FN_DEC | 3);

        t0 = kp[0];                         //  fetch even subkey
        t1 = kp[1];
        t2 = kp[2];
        t3 = kp[3];

        if (kp == rk)                       //  final round
            break;
        kp -= 8;

        t0 = enc1s(t0, u0, AES_FN_DEC);     //  AES decryption round, 16 instr
        t0 = enc1s(t0, u3, AES_FN_DEC | 1);
        t0 = enc1s(t0, u2, AES_FN_DEC | 2);
        t0 = enc1s(t0, u1, AES_FN_DEC | 3);

        t1 = enc1s(t1, u1, AES_FN_DEC);
        t1 = enc1s(t1, u0, AES_FN_DEC | 1);
        t1 = enc1s(t1, u3, AES_FN_DEC | 2);
        t1 = enc1s(t1, u2, AES_FN_DEC | 3);

        t2 = enc1s(t2, u2, AES_FN_DEC);
        t2 = enc1s(t2, u1, AES_FN_DEC | 1);
        t2 = enc1s(t2, u0, AES_FN_DEC | 2);
        t2 = enc1s(t2, u3, AES_FN_DEC | 3);

        t3 = enc1s(t3, u3, AES_FN_DEC);
        t3 = enc1s(t3, u2, AES_FN_DEC | 1);
        t3 = enc1s(t3, u1, AES_FN_DEC | 2);
        t3 = enc1s(t3, u0, AES_FN_DEC | 3);
    }

    t0 = enc1s(t0, u0, AES_FN_REV);         //  final decryption round, 16 ins.
    t0 = enc1s(t0, u3, AES_FN_REV | 1);
    t0 = enc1s(t0, u2, AES_FN_REV | 2);
    t0 = enc1s(t0, u1, AES_FN_REV | 3);

    t1 = enc1s(t1, u1, AES_FN_REV);
    t1 = enc1s(t1, u0, AES_FN_REV | 1);
    t1 = enc1s(t1, u3, AES_FN_REV | 2);
    t1 = enc1s(t1, u2, AES_FN_REV | 3);

    t2 = enc1s(t2, u2, AES_FN_REV);
    t2 = enc1s(t2, u1, AES_FN_REV | 1);
    t2 = enc1s(t2, u0, AES_FN_REV | 2);
    t2 = enc1s(t2, u3, AES_FN_REV | 3);

    t3 = enc1s(t3, u3, AES_FN_REV);
    t3 = enc1s(t3, u2, AES_FN_REV | 1);
    t3 = enc1s(t3, u1, AES_FN_REV | 2);
    t3 = enc1s(t3, u0, AES_FN_REV | 3);

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
    uint32_t x;

    for (i = 0; i < len; i++) {
        x = v[i];

//      x = enc4s(x, 0, AES_FN_RMC);        //  Inverse MixColulmns
//      This is the only place where AES_FN_RMC is used. Slightly slower:

        x = enc4s(0, x, AES_FN_FWD);        //  SubWord()
        x = enc4s(0, x, AES_FN_DEC);        //  Just want inv MixCol()

        v[i] = x;
    }
}

//  Key schedule for AES-128 decryption.

void aes128_dec_key(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16])
{
    //  create an encryption key and modify middle rounds
    aes128_enc_key(rk, key);
    aes_dec_invmc(rk + 4, AES128_RK_WORDS - 8);
}

//  Key schedule for AES-192 decryption.

void aes192_dec_key(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24])
{
    //  create an encryption key and modify middle rounds
    aes192_enc_key(rk, key);
    aes_dec_invmc(rk + 4, AES192_RK_WORDS - 8);
}

//  Key schedule for AES-256 decryption.

void aes256_dec_key(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32])
{
    //  create an encryption key and modify middle rounds
    aes256_enc_key(rk, key);
    aes_dec_invmc(rk + 4, AES256_RK_WORDS - 8);
}

