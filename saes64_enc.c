//  saes64_enc.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "Running pseudocode" for full AES-128/192/256 encryption.

#include "aes_wrap.h"
#include "bitmanip.h"
#include "endian.h"
#include "crypto_rv64.h"

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

	u0 = saes64_encsm(t0, t1);
	u1 = saes64_encsm(t1, t0);
	k0 = kp[2];
	k1 = kp[3];
	u0 = u0 ^ k0;
	u1 = u1 ^ k1;

	do {

		kp += 4;

		t0 = saes64_encsm(u0, u1);
		t1 = saes64_encsm(u1, u0);
		k0 = kp[0];
		k1 = kp[1];
		t0 = t0 ^ k0;
		t1 = t1 ^ k1;

		u0 = saes64_encsm(t0, t1);
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
