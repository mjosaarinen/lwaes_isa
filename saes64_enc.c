//  saes64_enc.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  SAES64: Proposed RV64 AES Extension.
//  "Running pseudocode" for full AES-128/192/256 encryption.

#include "aes_wrap.h"
#include "rv_endian.h"
#include "crypto_saes64.h"

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

//  Per round: 2 * ENCSM, 2 * load, 2 * XOR

#define SAES64_ENC_ROUND(r0, r1, s0, s1, i) {	\
	r0 = saes64_encsm(s0, s1);	\
	r1 = saes64_encsm(s1, s0);	\
	k0 = kp[2 * i];				\
	k1 = kp[2 * i + 1];			\
	r0 = r0 ^ k0;				\
	r1 = r1 ^ k1;				}

void saes64_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
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

//  Key schedule for AES-128 Encryption.
//  For each round 1 * SAES64.KS1, 2 * SAES64.KS2 and 2 * store

#define SAES64_KEY128_STEP(i) {	\
	kp[2 * i] 	= k0;			\
	kp[2 * i + 1] = k1;			\
	ks = saes64_ks1(k1, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1); 	}

void saes64_enc_key128(uint32_t rk[44], const uint8_t key[16])
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

void saes64_enc_key192(uint32_t rk[52], const uint8_t key[24])
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

void saes64_enc_key256(uint32_t rk[60], const uint8_t key[32])
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
