//  aes_wrap.h
//  2019-10-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2019, PQShield Ltd. All rights reserved.

//  AES 128/192/256 block encryption and decryption (no dependencies)

#ifndef _AES_WRAP_H_
#define _AES_WRAP_H_

#include <stdint.h>
#include <stddef.h>

//  number of rounds
#define AES128_ROUNDS 10
#define AES192_ROUNDS 12
#define AES256_ROUNDS 14

//  expanded key size
#define AES128_RK_WORDS (4 * (AES128_ROUNDS + 1))
#define AES192_RK_WORDS (4 * (AES192_ROUNDS + 1))
#define AES256_RK_WORDS (4 * (AES256_ROUNDS + 1))

//  === ENCRYPT UUT ===

//  set encryption key
extern void (*aes128_enc_key)(uint32_t rk[AES128_RK_WORDS],
							  const uint8_t key[16]);
extern void (*aes192_enc_key)(uint32_t rk[AES192_RK_WORDS],
							  const uint8_t key[24]);
extern void (*aes256_enc_key)(uint32_t rk[AES256_RK_WORDS],
							  const uint8_t key[32]);

//  encrypt a block
extern void (*aes_enc_rounds)(uint8_t ct[16], const uint8_t pt[16],
							  const uint32_t rk[], int nr);

//  implementations 
void saes32_enc_key_128(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);
void saes32_enc_key_192(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);
void saes32_enc_key_256(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);

void saes32_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[], int nr);
void saes64_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[], int nr);

//  aliases
#define aes128_enc_ecb(ct, pt, rk) aes_enc_rounds(ct, pt, rk, AES128_ROUNDS);
#define aes192_enc_ecb(ct, pt, rk) aes_enc_rounds(ct, pt, rk, AES192_ROUNDS);
#define aes256_enc_ecb(ct, pt, rk) aes_enc_rounds(ct, pt, rk, AES256_ROUNDS);

//  === DECRYPT ===

//  set decryption key
extern void (*aes128_dec_key)(uint32_t rk[AES128_RK_WORDS],
							  const uint8_t key[16]);
extern void (*aes192_dec_key)(uint32_t rk[AES192_RK_WORDS],
							  const uint8_t key[24]);
extern void (*aes256_dec_key)(uint32_t rk[AES256_RK_WORDS],
							  const uint8_t key[32]);

//  pointer to uut
extern void (*aes_dec_rounds)(uint8_t pt[16], const uint8_t ct[16],
							  const uint32_t rk[], int nr);

//  implementations
void saes32_dec_key_128(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);
void saes32_dec_key_192(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);
void saes32_dec_key_256(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);

void saes32_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[], int nr);
void saes64_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[], int nr);

//  aliases
#define aes128_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES128_ROUNDS);
#define aes192_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES192_ROUNDS);
#define aes256_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES256_ROUNDS);

#endif										//  _AES_WRAP_H_
