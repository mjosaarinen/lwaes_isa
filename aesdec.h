//  aesdec.h
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  AES 128/192/256 block decryption

#ifndef _AESDEC_H_
#define _AESDEC_H_

#include "aesenc.h"

//  Inverse S-Box lookup and partial MixColumn(), 7-bit fn (5 bits used)
uint32_t aes_dec1s(uint32_t rs1, uint32_t rs2, int fn);

//  API:

//  set decryption key
void aes128_dec_key(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);
void aes192_dec_key(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);
void aes256_dec_key(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);

//  decrypt a block
void aes_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
                    const uint32_t rk[], int nr);

//  aliases
#define aes128_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES128_ROUNDS);
#define aes192_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES192_ROUNDS);
#define aes256_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES256_ROUNDS);

#endif                          /* _AESDEC_H_ */
