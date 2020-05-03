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


#include "crypto_saes32.h"

//  round constants -- just iterations of the xtime() LFSR

static const uint8_t aes_rcon[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

//  XXXXXXX THIS PART IS STILL MISSING

uint64_t saes64_ks1(uint64_t rs1, uint8_t i);

//  Key schedule for AES-128 Encryption.

void saes64_enc_key128(uint32_t rk[44], const uint8_t key[16])
{
	uint32_t t0, t1, t2, t3, tr;			//  subkey registers
	const uint32_t *rke = &rk[44 - 4];		//  end pointer
	const uint8_t *rc = aes_rcon;			//  round constants

	t0 = get32u_le(key);					//  load secret key
	t1 = get32u_le(key + 4);
	t2 = get32u_le(key + 8);
	t3 = get32u_le(key + 12);

	while (1) {

		rk[0] = t0;							//  store subkey
		rk[1] = t1;
		rk[2] = t2;
		rk[3] = t3;

		if (rk == rke)						//  end condition
			return;
		rk += 4;							//  step pointer by one subkey

		t0 ^= (uint32_t) * rc++;			//  round constant
		tr = rv32b_ror(t3, 8);				//  rotate 8 bits (little endian!)
		t0 = saes32_encs(t0, tr, 0);		//  SubWord()
		t0 = saes32_encs(t0, tr, 1);
		t0 = saes32_encs(t0, tr, 2);
		t0 = saes32_encs(t0, tr, 3);
		t1 ^= t0;
		t2 ^= t1;
		t3 ^= t2;
	}
}

//  Key schedule for AES-192 encryption.

void saes64_enc_key192(uint32_t rk[52], const uint8_t key[24])
{
	uint32_t t0, t1, t2, t3, t4, t5, tr;	//  subkey registers
	const uint32_t *rke = &rk[52 - 4];		//  end pointer
	const uint8_t *rc = aes_rcon;			//  round constants

	t0 = get32u_le(key);					//  load secret key
	t1 = get32u_le(key + 4);
	t2 = get32u_le(key + 8);
	t3 = get32u_le(key + 12);
	t4 = get32u_le(key + 16);
	t5 = get32u_le(key + 20);

	while (1) {

		rk[0] = t0;							//  store subkey (or part)
		rk[1] = t1;
		rk[2] = t2;
		rk[3] = t3;
		if (rk == rke)						//  end condition
			return;
		rk[4] = t4;
		rk[5] = t5;
		rk += 6;							//  step pointer by 1.5 subkeys

		t0 ^= (uint32_t) * rc++;			//  round constant
		tr = rv32b_ror(t5, 8);				//  rotate 8 bits (little endian!)
		t0 = saes32_encs(t0, tr, 0);		//  SubWord()
		t0 = saes32_encs(t0, tr, 1);
		t0 = saes32_encs(t0, tr, 2);
		t0 = saes32_encs(t0, tr, 3);

		t1 ^= t0;
		t2 ^= t1;
		t3 ^= t2;
		t4 ^= t3;
		t5 ^= t4;
	}
}

//  Key schedule for AES-256 encryption.

void saes64_enc_key256(uint32_t rk[60], const uint8_t key[32])
{
	uint32_t t0, t1, t2, t3, t4, t5, t6, t7, tr;	// subkey registers
	const uint32_t *rke = &rk[60 - 4];		//  end pointer
	const uint8_t *rc = aes_rcon;			//  round constants

	t0 = get32u_le(key);
	t1 = get32u_le(key + 4);
	t2 = get32u_le(key + 8);
	t3 = get32u_le(key + 12);
	t4 = get32u_le(key + 16);
	t5 = get32u_le(key + 20);
	t6 = get32u_le(key + 24);
	t7 = get32u_le(key + 28);

	rk[0] = t0;								//  store first subkey
	rk[1] = t1;
	rk[2] = t2;
	rk[3] = t3;

	while (1) {

		rk[4] = t4;							//  store odd subkey
		rk[5] = t5;
		rk[6] = t6;
		rk[7] = t7;
		rk += 8;							//  step pointer by 2 subkeys

		t0 ^= (uint32_t) * rc++;			//  round constant
		tr = rv32b_ror(t7, 8);				//  rotate 8 bits (little endian!)
		t0 = saes32_encs(t0, tr, 0);		//  SubWord()
		t0 = saes32_encs(t0, tr, 1);
		t0 = saes32_encs(t0, tr, 2);
		t0 = saes32_encs(t0, tr, 3);
		t1 ^= t0;
		t2 ^= t1;
		t3 ^= t2;

		rk[0] = t0;							//  store even subkey
		rk[1] = t1;
		rk[2] = t2;
		rk[3] = t3;
		if (rk == rke)						//  end condition
			return;

		t4 = saes32_encs(t4, t3, 0);		//  SubWord() - NO rotation
		t4 = saes32_encs(t4, t3, 1);
		t4 = saes32_encs(t4, t3, 2);
		t4 = saes32_encs(t4, t3, 3);
		t5 ^= t4;
		t6 ^= t5;
		t7 ^= t6;
	}
}
