//  aes_wrap.c
//  2020-04-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  AES 128/192/256 block encryption and decryption

#include "aes_wrap.h"

//  == Externally visible pointers ==

//  encryption keying

void (*aes128_enc_key)(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16])
	= saes32_128_enc_key;
void (*aes192_enc_key)(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24])
	= saes32_192_enc_key;
void (*aes256_enc_key)(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32])
	= saes32_256_enc_key;

//  encryption

void (*aes_enc_rounds)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[], int nr) = aes_saes32_enc;

//  decryption keying

void (*aes128_dec_key)(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16])
	= saes32_128_dec_key;
void (*aes192_dec_key)(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24])
	= saes32_192_dec_key;
void (*aes256_dec_key)(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32])
	= saes32_256_dec_key;

//  decryption

void (*aes_dec_rounds)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[], int nr) = aes_saes32_dec;
