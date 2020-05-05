//  aes_saes32.h
//  2020-05-05  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Implementation prototypes for aes_saes32.c

#ifndef _AES_SAES32_H_
#define _AES_SAES32_H_

#include <stdint.h>

//  Set encryption key

void aes128_enc_key_saes32(uint32_t rk[AES128_RK_WORDS],
						   const uint8_t key[16]);

void aes192_enc_key_saes32(uint32_t rk[AES192_RK_WORDS],
						   const uint8_t key[24]);

void aes256_enc_key_saes32(uint32_t rk[AES256_RK_WORDS],
						   const uint8_t key[32]);

//  Encrypt a block

void aes128_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t rk[AES128_RK_WORDS]);

void aes192_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t rk[AES192_RK_WORDS]);

void aes256_enc_ecb_saes32(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t rk[AES256_RK_WORDS]);


//  Set decryption key

void aes128_dec_key_saes32(uint32_t rk[AES128_RK_WORDS],
						   const uint8_t key[16]);

void aes192_dec_key_saes32(uint32_t rk[AES192_RK_WORDS],
						   const uint8_t key[24]);

void aes256_dec_key_saes32(uint32_t rk[AES256_RK_WORDS],
						   const uint8_t key[32]);

//  Decrypt a block

void aes128_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16],
						   const uint32_t rk[AES128_RK_WORDS]);

void aes192_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16],
						   const uint32_t rk[AES192_RK_WORDS]);

void aes256_dec_ecb_saes32(uint8_t pt[16], const uint8_t ct[16],
						   const uint32_t rk[AES256_RK_WORDS]);

#endif										//  _AES_SAES32_H_
