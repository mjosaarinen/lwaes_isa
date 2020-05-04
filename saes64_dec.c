//  saes64_dec.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	SAES64: Proposed RV64 AES Extension.
//  "Running pseudocode" for full AES-128/192/256 decryption.

#include "aes_wrap.h"
#include "rv_endian.h"
#include "crypto_saes64.h"

//  Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

//	Per round: 2 * load, 2 * XOR, 2 * DECSM

#define SAES64_DEC_ROUND(r0, r1, s0, s1, i) {	\
	k0 = kp[2 * i + 2];			\
	k1 = kp[2 * i + 3];			\
	s0 = s0 ^ k0;				\
	s1 = s1 ^ k1;				\
	r0 = saes64_decsm(s0, s1);	\
	r1 = saes64_decsm(s1, s0);	}


void saes64_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[], int nr)
{
	//  key pointer (just  a cast)
	const uint64_t *kp = (const uint64_t *) rk;
	
	uint64_t t0, t1, u0, u1, k0, k1;

	t0 = ((const uint64_t *) ct)[0];		//  get ciphertext
	t1 = ((const uint64_t *) ct)[1];

	if (nr >= 12) {
		if (nr > 12) {						//	AES-256
			SAES64_DEC_ROUND(u0, u1, t0, t1, 13);
			SAES64_DEC_ROUND(t0, t1, u0, u1, 12);
		}									//	AES-192, AES-192
		SAES64_DEC_ROUND(u0, u1, t0, t1, 11);
		SAES64_DEC_ROUND(t0, t1, u0, u1, 10);
	}
	
	SAES64_DEC_ROUND(u0, u1, t0, t1, 9);	//	6 insn / round
	SAES64_DEC_ROUND(t0, t1, u0, u1, 8);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 7);
	SAES64_DEC_ROUND(t0, t1, u0, u1, 6);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 5);
	SAES64_DEC_ROUND(t0, t1, u0, u1, 4);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 3);
	SAES64_DEC_ROUND(t0, t1, u0, u1, 2);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 1);

	k0 = kp[2];								//	final decrypt round
	k1 = kp[3];
	u0 = u0 ^ k0;
	u1 = u1 ^ k1;
	t0 = saes64_decs(u0, u1);				//	DECS instead of DECSM
	t1 = saes64_decs(u1, u0);
	k0 = kp[0];								//  first round key
	k1 = kp[1];
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	((uint64_t *) pt)[0] = t0;				//  store plaintext
	((uint64_t *) pt)[1] = t1;

	return;

}

#include "crypto_saes32.h"
#include <stdio.h>

//  Helper: apply inverse mixcolumns to a vector
//  If decryption keys are computed in the fly (inverse key schedule), there's

void saes64_dec_invmc(uint64_t * v, size_t len)
{
	size_t i;
	uint64_t x;

	for (i = 0; i < len; i++) {
		x = v[i];
		x = saes64_imix(x);
		v[i] = x;
	}
}

//  Key schedule for AES-128 decryption.

void saes64_dec_key128(uint32_t rk[44], const uint8_t key[16])
{
	//  create an encryption key and modify middle rounds
	saes64_enc_key128(rk, key);
	saes64_dec_invmc(((uint64_t *) rk) + 2, AES128_RK_WORDS / 2 - 4);
}

//  Key schedule for AES-192 decryption.

void saes64_dec_key192(uint32_t rk[52], const uint8_t key[24])
{
	//  create an encryption key and modify middle rounds
	saes64_enc_key192(rk, key);
	saes64_dec_invmc(((uint64_t *) rk) + 2, AES192_RK_WORDS / 2 - 4);
}

//  Key schedule for AES-256 decryption.

void saes64_dec_key256(uint32_t rk[60], const uint8_t key[32])
{
	//  create an encryption key and modify middle rounds
	saes64_enc_key256(rk, key);
	saes64_dec_invmc(((uint64_t *) rk) + 2, AES256_RK_WORDS / 2 - 4);
}
