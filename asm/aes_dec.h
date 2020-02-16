//	aes_dec.h
//	2020-01-22	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	AES 128/192/256 block decryption

#ifndef _AES_DEC_H_
#define _AES_DEC_H_

#include "aes_enc.h"

//	set decryption key
void aes128_dec_key(uint32_t rk[AES128_RK_WORDS], const uint8_t key[16]);
void aes192_dec_key(uint32_t rk[AES192_RK_WORDS], const uint8_t key[24]);
void aes256_dec_key(uint32_t rk[AES256_RK_WORDS], const uint8_t key[32]);

//	decrypt a block
void aes_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
					const uint32_t rk[], int nr);

//	aliases
#define aes128_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES128_ROUNDS);
#define aes192_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES192_ROUNDS);
#define aes256_dec_ecb(ct, pt, rk) aes_dec_rounds(ct, pt, rk, AES256_ROUNDS);

#endif							/* _AES_DEC_H_ */
