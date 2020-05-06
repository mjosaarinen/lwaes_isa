//  aes_saes64.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "Running pseudocode" for full AES-128/192/256 encryption and decryption
//  using SAES64.xxx instructions.

#include <stddef.h>

#include "aes_wrap.h"
#include "saes64.h"
#include "rv_endian.h"

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

//  Per round: 2 * ENCSM, 2 * load, 2 * XOR

#define SAES64_ENC_ROUND(r0, r1, s0, s1, i) {	\
	r0 = saes64_encsm(s0, s1);	\
	r1 = saes64_encsm(s1, s0);	\
	k0 = kp[2 * i];				\
	k1 = kp[2 * i + 1];			\
	r0 = r0 ^ k0;				\
	r1 = r1 ^ k1;				}

void aes_enc_rounds_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t rk[], int nr)
{
	//  key pointer
	const uint64_t *kp = (const uint64_t *) rk;

	uint64_t t0, t1, u0, u1, k0, k1;

	t0 = ((const uint64_t *) pt)[0];		//  get plaintext
	t1 = ((const uint64_t *) pt)[1];

	k0 = kp[0];								//  load first round
	k1 = kp[1];
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	SAES64_ENC_ROUND(u0, u1, t0, t1, 1);	//  6 insn / round
	SAES64_ENC_ROUND(t0, t1, u0, u1, 2);
	SAES64_ENC_ROUND(u0, u1, t0, t1, 3);
	SAES64_ENC_ROUND(t0, t1, u0, u1, 4);
	SAES64_ENC_ROUND(u0, u1, t0, t1, 5);
	SAES64_ENC_ROUND(t0, t1, u0, u1, 6);
	SAES64_ENC_ROUND(u0, u1, t0, t1, 7);
	SAES64_ENC_ROUND(t0, t1, u0, u1, 8);
	SAES64_ENC_ROUND(u0, u1, t0, t1, 9);

	//  In reality we would entirely inline these for all 128/192/256 versions

	if (nr >= 12) {							//  AES-192, AES-256
		SAES64_ENC_ROUND(t0, t1, u0, u1, 10);
		SAES64_ENC_ROUND(u0, u1, t0, t1, 11);
		if (nr > 12) {
			SAES64_ENC_ROUND(t0, t1, u0, u1, 12);
			SAES64_ENC_ROUND(u0, u1, t0, t1, 13);
			k0 = kp[2 * 14];				//  AES-256 last round key
			k1 = kp[2 * 14 + 1];
		} else {
			k0 = kp[2 * 12];				//  AES-192 last round key
			k1 = kp[2 * 12 + 1];
		}
	} else {
		k0 = kp[2 * 10];					//  AES-128 last round key
		k1 = kp[2 * 10 + 1];
	}

	t0 = saes64_encs(u0, u1);				//  Final round; ENCS not ENCSM
	t1 = saes64_encs(u1, u0);
	t0 = t0 ^ k0;							//  last round key
	t1 = t1 ^ k1;

	((uint64_t *) ct)[0] = t0;				//  store ciphertext
	((uint64_t *) ct)[1] = t1;
}

//  Wrappers

void aes128_enc_ecb_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t rk[AES128_RK_WORDS])
{
	aes_enc_rounds_saes64(ct, pt, rk, AES128_ROUNDS);
}

void aes192_enc_ecb_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t rk[AES192_RK_WORDS])
{
	aes_enc_rounds_saes64(ct, pt, rk, AES192_ROUNDS);
}

void aes256_enc_ecb_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t rk[AES256_RK_WORDS])
{
	aes_enc_rounds_saes64(ct, pt, rk, AES256_ROUNDS);
}

//  Key schedule for AES-128 Encryption.
//  For each round 1 * SAES64.KS1, 2 * SAES64.KS2 and 2 * store

#define SAES64_KEY128_STEP(i) {	\
	kp[2 * i] 	= k0;			\
	kp[2 * i + 1] = k1;			\
	ks = saes64_ks1(k1, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1); 	}

void aes128_enc_key_saes64(uint32_t rk[44], const uint8_t key[16])
{
	uint64_t *kp = (uint64_t *) rk;			//  key pointer
	uint64_t k0, k1, ks;

	k0 = get64u_le(key);					//  load secret key
	k1 = get64u_le(key + 8);
	SAES64_KEY128_STEP(0);					//  5 insn each, unrolled
	SAES64_KEY128_STEP(1);
	SAES64_KEY128_STEP(2);
	SAES64_KEY128_STEP(3);
	SAES64_KEY128_STEP(4);
	SAES64_KEY128_STEP(5);
	SAES64_KEY128_STEP(6);
	SAES64_KEY128_STEP(7);
	SAES64_KEY128_STEP(8);
	SAES64_KEY128_STEP(9);					//  (10 steps, 10 rounds)
	kp[20] = k0;							//  last round key
	kp[21] = k1;
}

//  Key schedule for AES-192 encryption.
//  For each 1.5 rounds 1 * SAES64.KS1, 3 * SAES64.KS2 and 3 * store

#define SAES64_KEY192_STEP(i) {	\
	kp[3 * i] 	= k0;			\
	kp[3 * i + 1] = k1;			\
	kp[3 * i + 2] = k2;			\
	ks = saes64_ks1(k2, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1);	\
	k2 = saes64_ks2(k1, k2); 	}

void aes192_enc_key_saes64(uint32_t rk[52], const uint8_t key[24])
{
	uint64_t *kp = (uint64_t *) rk;			//  key pointer
	uint64_t k0, k1, k2, ks;

	k0 = get64u_le(key);					//  load secret key
	k1 = get64u_le(key + 8);
	k2 = get64u_le(key + 16);
	SAES64_KEY192_STEP(0);					//  two steps is 3 rounds
	SAES64_KEY192_STEP(1);					//  14/3 = 4.7 insn/round
	SAES64_KEY192_STEP(2);
	SAES64_KEY192_STEP(3);
	SAES64_KEY192_STEP(4);
	SAES64_KEY192_STEP(5);
	SAES64_KEY192_STEP(6);
	kp[21] = k0;							//  last full state
	kp[22] = k1;
	kp[23] = k2;
	ks = saes64_ks1(k2, 7);					//  (8 steps, 12 rounds)
	k0 = saes64_ks2(ks, k0);
	k1 = saes64_ks2(k0, k1);				//  no need for k2
	kp[24] = k0;							//  last round key
	kp[25] = k1;
}

//  Key schedule for AES-256 encryption.
//  For each 2 rounds: 2 * SAES64.KS1, 4 * SAES64.KS2 and 4 * store

#define SAES64_KEY256_STEP(i) {	\
	kp[4 * i] 	= k0;			\
	kp[4 * i + 1] = k1;			\
	kp[4 * i + 2] = k2;			\
	kp[4 * i + 3] = k3;			\
	ks = saes64_ks1(k3, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1);	\
	ks = saes64_ks1(k1, 10);	\
	k2 = saes64_ks2(ks, k2);	\
	k3 = saes64_ks2(k2, k3); 	}

void aes256_enc_key_saes64(uint32_t rk[60], const uint8_t key[32])
{
	uint64_t *kp = (uint64_t *) rk;			//  key pointer
	uint64_t k0, k1, k2, k3, ks;

	k0 = get64u_le(key);					//  load secret key
	k1 = get64u_le(key + 8);
	k2 = get64u_le(key + 16);
	k3 = get64u_le(key + 24);
	SAES64_KEY256_STEP(0);					//  1 steps is 2 rounds
	SAES64_KEY256_STEP(1);					//  10/2 = 5 insn/round
	SAES64_KEY256_STEP(2);
	SAES64_KEY256_STEP(3);
	SAES64_KEY256_STEP(4);
	SAES64_KEY256_STEP(5);
	kp[24] = k0;							//  store last full state
	kp[25] = k1;
	kp[26] = k2;
	kp[27] = k3;
	ks = saes64_ks1(k3, 6);					//  no need for k2, k3
	k0 = saes64_ks2(ks, k0);
	k1 = saes64_ks2(k0, k1);
	kp[28] = k0;							//  store last round key
	kp[29] = k1;
}

//  Decrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

//  Per round: 2 * load, 2 * XOR, 2 * DECSM

#define SAES64_DEC_ROUND(r0, r1, s0, s1, i) {	\
	k0 = kp[2 * i + 2];			\
	k1 = kp[2 * i + 3];			\
	s0 = s0 ^ k0;				\
	s1 = s1 ^ k1;				\
	r0 = saes64_decsm(s0, s1);	\
	r1 = saes64_decsm(s1, s0);	}


void aes_dec_rounds_saes64(uint8_t pt[16], const uint8_t ct[16],
						   const uint32_t rk[], int nr)
{
	//  key pointer (just  a cast)
	const uint64_t *kp = (const uint64_t *) rk;

	uint64_t t0, t1, u0, u1, k0, k1;

	t0 = ((const uint64_t *) ct)[0];		//  get ciphertext
	t1 = ((const uint64_t *) ct)[1];

	//  In reality we would entirely inline these for all 128/192/256 versions

	if (nr >= 12) {
		if (nr > 12) {						//  AES-256
			SAES64_DEC_ROUND(u0, u1, t0, t1, 13);
			SAES64_DEC_ROUND(t0, t1, u0, u1, 12);
		}									//  AES-192, AES-192
		SAES64_DEC_ROUND(u0, u1, t0, t1, 11);
		SAES64_DEC_ROUND(t0, t1, u0, u1, 10);
	}

	SAES64_DEC_ROUND(u0, u1, t0, t1, 9);	//  6 insn / round
	SAES64_DEC_ROUND(t0, t1, u0, u1, 8);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 7);
	SAES64_DEC_ROUND(t0, t1, u0, u1, 6);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 5);
	SAES64_DEC_ROUND(t0, t1, u0, u1, 4);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 3);
	SAES64_DEC_ROUND(t0, t1, u0, u1, 2);
	SAES64_DEC_ROUND(u0, u1, t0, t1, 1);

	k0 = kp[2];								//  final decrypt round
	k1 = kp[3];
	u0 = u0 ^ k0;
	u1 = u1 ^ k1;
	t0 = saes64_decs(u0, u1);				//  DECS instead of DECSM
	t1 = saes64_decs(u1, u0);
	k0 = kp[0];								//  first round key
	k1 = kp[1];
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	((uint64_t *) pt)[0] = t0;				//  store plaintext
	((uint64_t *) pt)[1] = t1;

	return;

}

//  Wrappers

void aes128_dec_ecb_saes64(uint8_t pt[16], const uint8_t ct[16],
						   const uint32_t rk[AES128_RK_WORDS])
{
	aes_dec_rounds_saes64(pt, ct, rk, AES128_ROUNDS);
}

void aes192_dec_ecb_saes64(uint8_t pt[16], const uint8_t ct[16],
						   const uint32_t rk[AES192_RK_WORDS])
{
	aes_dec_rounds_saes64(pt, ct, rk, AES192_ROUNDS);
}

void aes256_dec_ecb_saes64(uint8_t pt[16], const uint8_t ct[16],
						   const uint32_t rk[AES256_RK_WORDS])
{
	aes_dec_rounds_saes64(pt, ct, rk, AES256_ROUNDS);
}

//  Helper: apply inverse mixcolumns to a vector

static inline void saes64_dec_invmc(uint64_t * v, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		v[i] = saes64_imix(v[i]);
	}
}

//  Key schedule for AES-128 decryption.

void aes128_dec_key_saes64(uint32_t rk[44], const uint8_t key[16])
{
	//  create an encryption key and modify middle rounds
	aes128_enc_key_saes64(rk, key);
	saes64_dec_invmc(((uint64_t *) rk) + 2, AES128_RK_WORDS / 2 - 4);
}

//  Key schedule for AES-192 decryption.

void aes192_dec_key_saes64(uint32_t rk[52], const uint8_t key[24])
{
	//  create an encryption key and modify middle rounds
	aes192_enc_key_saes64(rk, key);
	saes64_dec_invmc(((uint64_t *) rk) + 2, AES192_RK_WORDS / 2 - 4);
}

//  Key schedule for AES-256 decryption.

void aes256_dec_key_saes64(uint32_t rk[60], const uint8_t key[32])
{
	//  create an encryption key and modify middle rounds
	aes256_enc_key_saes64(rk, key);
	saes64_dec_invmc(((uint64_t *) rk) + 2, AES256_RK_WORDS / 2 - 4);
}
