//  aes_gcm.c
//  2020-03-21  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  A basic AES-GCM AEAD interface
//  CM_GCM_MUL -- controls "constant time" functionality

#include <string.h>

#include "aes_enc.h"
#include "aes_gcm.h"

#ifndef GETU32_BE
#define GETU32_BE(v) \
		(((uint32_t)(v)[0] << 24) ^	((uint32_t)(v)[1] << 16) ^ \
		((uint32_t)(v)[2] <<  8)  ^ ((uint32_t)(v)[3]))
#endif										/* !GETU32_BE */

#ifndef PUTU32_BE
#define PUTU32_BE(v, x) {\
	(v)[0] = (uint8_t)((x) >> 24);	(v)[1] = (uint8_t)((x) >> 16); \
	(v)[2] = (uint8_t)((x) >>  8);  (v)[3] = (uint8_t)(x);  }
#endif										/* !PUTU32_BE */

#include <stdio.h>

void prt128(const uint8_t v[16])
{
	size_t i;

	for (i = 0; i < 16; i++)
		printf("%02X", v[i]);
}

//  slow galois field multiplication ("constant time")

static void gf128mul(uint8_t z[16], const uint8_t x[16], const uint8_t y[16])
{
	int i;
	uint32_t z0, z1, z2, z3, x0, x1, x2, x3, f;

	prt128(x);
	printf(" * ");
	prt128(y);

	x3 = GETU32_BE(x);
	x2 = GETU32_BE(x + 4);
	x1 = GETU32_BE(x + 8);
	x0 = GETU32_BE(x + 12);

	f = -(y[15] & 1);
	z0 = f & x0;
	z1 = f & x1;
	z2 = f & x2;
	z3 = f & x3;

	for (i = 1; i < 128; i++) {

		f = -(z0 & 1);
		z0 = (z0 >> 1) ^ (z1 << 31);
		z1 = (z1 >> 1) ^ (z2 << 31);
		z2 = (z2 >> 1) ^ (z3 << 31);
		z3 = (z3 >> 1) ^ (0xE1000000 & f);

		f = -((y[15 - (i >> 3)] >> (i & 7)) & 1);
		z0 ^= x0 & f;
		z1 ^= x1 & f;
		z2 ^= x2 & f;
		z3 ^= x3 & f;
	}

	PUTU32_BE(z, z3);
	PUTU32_BE(z + 4, z2);
	PUTU32_BE(z + 8, z1);
	PUTU32_BE(z + 12, z0);

	printf(" = ");
	prt128(z);
	printf("\n");
}


//  the same "body" for encryption/decryption, different key lengths

static void aes_gcm_body(uint8_t * dst, uint8_t tag[16],
						 const uint8_t * src, size_t len,
						 const uint8_t iv[12], const uint32_t rk[], int nr,
						 int enc_flag)
{
	uint8_t ctr[16], blk[16], sum[16];
	size_t i, j, k;

	uint8_t h[16];

	memset(h, 0, 16);						// h = 0
	aes_enc_rounds(h, h, rk, nr);

	memcpy(ctr, iv, 12);					// J0
	ctr[12] = 0x00;
	ctr[13] = 0x00;
	ctr[14] = 0x00;
	ctr[15] = 0x01;
	aes_enc_rounds(tag, ctr, rk, nr);

	memset(sum, 0, 16);

	for (i = 0; i < len; i += 16) {

		for (j = 15; j >= 12; j--) {		// inc counter
			ctr[j]++;
			if (ctr[j] != 0)
				break;
		}

		aes_enc_rounds(blk, ctr, rk, nr);	// xor mask
		k = len - i;
		if (k > 16)
			k = 16;

		if (enc_flag) {
			for (j = 0; j < k; j++) {		// encrypt block
				dst[i + j] = src[i + j] ^ blk[j];
				sum[j] ^= dst[i + j];
			}
		} else {
			for (j = 0; j < k; j++) {		// decrypt block
				sum[j] ^= src[i + j];
				dst[i + j] = src[i + j] ^ blk[j];
			}
		}

		gf128mul(sum, sum, h);				// mult by h
	}

	i = len << 3;							// pad tag with bit length
	j = 15;
	while (i > 0) {
		sum[j--] ^= i & 0xFF;
		i >>= 8;
	}
	gf128mul(sum, sum, h);

	for (i = 0; i < 16; i++)				// write tag
		tag[i] ^= sum[i];
}

//  verify it

static int aes_gcm_vfy(uint8_t * m,
					   const uint8_t * c, size_t clen,
					   const uint8_t iv[12], const uint32_t rk[], int nr)
{
	size_t i;
	uint8_t tag[16], x;

	if (clen < 16)
		return -1;

	aes_gcm_body(m, tag, c, clen - 16, iv, rk, nr, 0);
	x = 0;
	for (i = 0; i < 16; i++)
		x |= tag[i] ^ c[clen - 16 + i];

	return x == 0 ? 0 : -2;
}

//  AES128-GCM

void aes128_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES128_RK_WORDS];

	aes128_enc_key(rk, key);
	aes_gcm_body(c, c + mlen, m, mlen, iv, rk, AES128_ROUNDS, 1);
}

int aes128_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES128_RK_WORDS];

	aes128_enc_key(rk, key);
	return aes_gcm_vfy(m, c, clen, iv, rk, AES128_ROUNDS);
}


//  AES192-GCM

void aes192_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES192_RK_WORDS];

	aes192_enc_key(rk, key);
	aes_gcm_body(c, c + mlen, m, mlen, iv, rk, AES192_ROUNDS, 1);
}

int aes192_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES192_RK_WORDS];

	aes192_enc_key(rk, key);
	return aes_gcm_vfy(m, c, clen, iv, rk, AES192_ROUNDS);
}

//  AES256-GCM

void aes256_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES256_RK_WORDS];

	aes256_enc_key(rk, key);
	aes_gcm_body(c, c + mlen, m, mlen, iv, rk, AES256_ROUNDS, 1);
}

int aes256_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES256_RK_WORDS];

	aes256_enc_key(rk, key);
	return aes_gcm_vfy(m, c, clen, iv, rk, AES256_ROUNDS);
}
