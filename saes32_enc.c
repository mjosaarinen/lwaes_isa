//  saes32_enc.c
//  2020-01-22  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "Running pseudocode" for full AES-128/192/256 encryption.

#include "crypto_saes32.h"
#include "aes_wrap.h"
#include "bitmanip.h"
#include "rv_endian.h"

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

void saes32_enc_rounds(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[], int nr)
{
	uint32_t t0, t1, t2, t3;				//  even round state registers
	uint32_t u0, u1, u2, u3;				//  odd round state registers
	const uint32_t *kp = &rk[4 * nr];		//  key pointer as loop condition

	t0 = rk[0];								//  fetch even subkey
	t1 = rk[1];
	t2 = rk[2];
	t3 = rk[3];

	t0 ^= get32u_le(pt);					//  xor with plaintext block
	t1 ^= get32u_le(pt + 4);
	t2 ^= get32u_le(pt + 8);
	t3 ^= get32u_le(pt + 12);

	while (1) {								//  double round

		u0 = rk[4];							//  fetch odd subkey
		u1 = rk[5];
		u2 = rk[6];
		u3 = rk[7];

		u0 = saes32_encsm(u0, t0, 0);		//  AES round, 16 instructions
		u0 = saes32_encsm(u0, t1, 1);
		u0 = saes32_encsm(u0, t2, 2);
		u0 = saes32_encsm(u0, t3, 3);

		u1 = saes32_encsm(u1, t1, 0);
		u1 = saes32_encsm(u1, t2, 1);
		u1 = saes32_encsm(u1, t3, 2);
		u1 = saes32_encsm(u1, t0, 3);

		u2 = saes32_encsm(u2, t2, 0);
		u2 = saes32_encsm(u2, t3, 1);
		u2 = saes32_encsm(u2, t0, 2);
		u2 = saes32_encsm(u2, t1, 3);

		u3 = saes32_encsm(u3, t3, 0);
		u3 = saes32_encsm(u3, t0, 1);
		u3 = saes32_encsm(u3, t1, 2);
		u3 = saes32_encsm(u3, t2, 3);

		t0 = rk[8];							//  fetch even subkey
		t1 = rk[9];
		t2 = rk[10];
		t3 = rk[11];

		rk += 8;							//  step key pointer
		if (rk == kp)						//  final round ?
			break;

		t0 = saes32_encsm(t0, u0, 0);		//  AES round, 16 instructions
		t0 = saes32_encsm(t0, u1, 1);
		t0 = saes32_encsm(t0, u2, 2);
		t0 = saes32_encsm(t0, u3, 3);

		t1 = saes32_encsm(t1, u1, 0);
		t1 = saes32_encsm(t1, u2, 1);
		t1 = saes32_encsm(t1, u3, 2);
		t1 = saes32_encsm(t1, u0, 3);

		t2 = saes32_encsm(t2, u2, 0);
		t2 = saes32_encsm(t2, u3, 1);
		t2 = saes32_encsm(t2, u0, 2);
		t2 = saes32_encsm(t2, u1, 3);

		t3 = saes32_encsm(t3, u3, 0);
		t3 = saes32_encsm(t3, u0, 1);
		t3 = saes32_encsm(t3, u1, 2);
		t3 = saes32_encsm(t3, u2, 3);
	}

	t0 = saes32_encs(t0, u0, 0);			//  final round is different
	t0 = saes32_encs(t0, u1, 1);
	t0 = saes32_encs(t0, u2, 2);
	t0 = saes32_encs(t0, u3, 3);

	t1 = saes32_encs(t1, u1, 0);
	t1 = saes32_encs(t1, u2, 1);
	t1 = saes32_encs(t1, u3, 2);
	t1 = saes32_encs(t1, u0, 3);

	t2 = saes32_encs(t2, u2, 0);
	t2 = saes32_encs(t2, u3, 1);
	t2 = saes32_encs(t2, u0, 2);
	t2 = saes32_encs(t2, u1, 3);

	t3 = saes32_encs(t3, u3, 0);
	t3 = saes32_encs(t3, u0, 1);
	t3 = saes32_encs(t3, u1, 2);
	t3 = saes32_encs(t3, u2, 3);

	put32u_le(ct, t0);						//  write ciphertext block
	put32u_le(ct + 4, t1);
	put32u_le(ct + 8, t2);
	put32u_le(ct + 12, t3);
}

//  round constants -- just iterations of the xtime() LFSR

static const uint8_t aes_rcon[] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

//  ( Note: RISC-V has enough registers to compute subkeys on the fly. )

//  Key schedule for AES-128 Encryption.

void saes32_enc_key128(uint32_t rk[44], const uint8_t key[16])
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

void saes32_enc_key192(uint32_t rk[52], const uint8_t key[24])
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

void saes32_enc_key256(uint32_t rk[60], const uint8_t key[32])
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
