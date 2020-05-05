//  aes_wrap.c
//  2020-04-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  AES 128/192/256 block encryption and decryption

#include <stdio.h>
#include <stdlib.h>

#include "aes_wrap.h"
#include "aes_saes32.h"

static void key_undef(uint32_t * rk, const uint8_t * key)
{
	(void) rk;
	(void) key;

	fprintf(stderr, "[DEAD] key_undef()\n");
	abort();
}

static void ciph_undef(uint8_t * d, const uint8_t * s, const uint32_t * rk)
{
	(void) d;
	(void) s;
	(void) rk;

	fprintf(stderr, "[DEAD] key_undef()\n");
	abort();
}

//  == Externally visible pointers ==

//  Set encryption key

void (*aes128_enc_key)(uint32_t rk[AES128_RK_WORDS],
					   const uint8_t key[16]) = key_undef;

void (*aes192_enc_key)(uint32_t rk[AES192_RK_WORDS],
					   const uint8_t key[24]) = key_undef;

void (*aes256_enc_key)(uint32_t rk[AES256_RK_WORDS],
					   const uint8_t key[32]) = key_undef;

//  Encrypt a block


void (*aes128_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[AES128_RK_WORDS]) = ciph_undef;

void (*aes192_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[AES192_RK_WORDS]) = ciph_undef;

void (*aes256_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[AES256_RK_WORDS]) = ciph_undef;

//  Set decryption key

void (*aes128_dec_key)(uint32_t rk[AES128_RK_WORDS],
					   const uint8_t key[16]) = key_undef;
void (*aes192_dec_key)(uint32_t rk[AES192_RK_WORDS],
					   const uint8_t key[24]) = key_undef;
void (*aes256_dec_key)(uint32_t rk[AES256_RK_WORDS],
					   const uint8_t key[32]) = key_undef;

//  Decrypt a block

void (*aes128_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[AES128_RK_WORDS]) = ciph_undef;

void (*aes192_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[AES192_RK_WORDS]) = ciph_undef;

void (*aes256_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[AES256_RK_WORDS]) = ciph_undef;
