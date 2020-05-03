//  saes64_enc.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "Running pseudocode" for full AES-128/192/256 encryption.

#include "aes_wrap.h"
#include "bitmanip.h"
#include "rv_endian.h"
#include "crypto_saes64.h"

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

void saes64_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[], int nr)
{
	//  key pointer
	const uint64_t *kp = (const uint64_t *) rk;

	//  end pointer as loop condition
	const uint64_t *ep = &kp[2 * (nr - 2)];

	uint64_t t0, t1, u0, u1, k0, k1;

	t0 = ((const uint64_t *) pt)[0];		//  get plaintext
	t1 = ((const uint64_t *) pt)[1];

	k0 = kp[0];								//  first round key
	k1 = kp[1];
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	u0 = saes64_encsm(t0, t1);				//  first round
	u1 = saes64_encsm(t1, t0);
	k0 = kp[2];
	k1 = kp[3];
	u0 = u0 ^ k0;
	u1 = u1 ^ k1;

	do {

		kp += 4;							//  advance by two rounds

		t0 = saes64_encsm(u0, u1);			//  six instructions per round
		t1 = saes64_encsm(u1, u0);
		k0 = kp[0];
		k1 = kp[1];
		t0 = t0 ^ k0;
		t1 = t1 ^ k1;

		u0 = saes64_encsm(t0, t1);			//  (double round in loop)  
		u1 = saes64_encsm(t1, t0);
		k0 = kp[2];
		k1 = kp[3];
		u0 = u0 ^ k0;
		u1 = u1 ^ k1;

	} while (kp != ep);

	t0 = saes64_encs(u0, u1);
	t1 = saes64_encs(u1, u0);
	k0 = kp[4];								//  last round key
	k1 = kp[5];
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	((uint64_t *) ct)[0] = t0;				//  store ciphertext
	((uint64_t *) ct)[1] = t1;

	return;

}

//  Key schedule for AES-128 Encryption.
//  For each round 1 * SAES64.KS1, 2 * SAES64.KS2 and 2 * store

#define SAES64_KEY128_STEP(i) {	\
	kp[2*i] 	= k0;			\
	kp[2*i + 1] = k1;			\
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
	kp[3*i] 	= k0;			\
	kp[3*i + 1] = k1;			\
	kp[3*i + 2] = k2;			\
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
	kp[4*i] 	= k0;			\
	kp[4*i + 1] = k1;			\
	kp[4*i + 2] = k2;			\
	kp[4*i + 3] = k3;			\
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
