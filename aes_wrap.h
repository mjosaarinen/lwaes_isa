//  aes_wrap.h
//  2019-10-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2019, PQShield Ltd. All rights reserved.

//  Wrapper for AES 128/192/256 block encryption and decryption.
//  These provide function pointers tothe UUT.

#ifndef _AES_WRAP_H_
#define _AES_WRAP_H_

#include <stdint.h>

//  number of rounds
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12
#define AES256_ROUNDS 14

//  expanded key size
#define AES128_RK_WORDS (4 * (AES128_ROUNDS + 1))
#define AES192_RK_WORDS (4 * (AES192_ROUNDS + 1))
#define AES256_RK_WORDS (4 * (AES256_ROUNDS + 1))

//  Set encryption key

extern void (*aes128_enc_key)(uint32_t rk[AES128_RK_WORDS],
							  const uint8_t key[16]);

extern void (*aes192_enc_key)(uint32_t rk[AES192_RK_WORDS],
							  const uint8_t key[24]);

extern void (*aes256_enc_key)(uint32_t rk[AES256_RK_WORDS],
							  const uint8_t key[32]);

//  Encrypt a block


extern void (*aes128_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
							  const uint32_t rk[AES128_RK_WORDS]);

extern void (*aes192_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
							  const uint32_t rk[AES192_RK_WORDS]);

extern void (*aes256_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
							  const uint32_t rk[AES256_RK_WORDS]);

//  Set decryption key

extern void (*aes128_dec_key)(uint32_t rk[AES128_RK_WORDS],
							  const uint8_t key[16]);
extern void (*aes192_dec_key)(uint32_t rk[AES192_RK_WORDS],
							  const uint8_t key[24]);
extern void (*aes256_dec_key)(uint32_t rk[AES256_RK_WORDS],
							  const uint8_t key[32]);

//  Decrypt a block

extern void (*aes128_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
							  const uint32_t rk[AES128_RK_WORDS]);

extern void (*aes192_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
							  const uint32_t rk[AES192_RK_WORDS]);

extern void (*aes256_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
							  const uint32_t rk[AES256_RK_WORDS]);

#endif										//  _AES_WRAP_H_
