//  saes64_dec.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  "Running pseudocode" for full AES-128/192/256 decryption.

#include "aes_wrap.h"
#include "bitmanip.h"
#include "endian.h"
#include "crypto_rv64.h"

//  Encrypt rounds. Implements AES-128/192/256 depending on nr = {10,12,14}

void saes64_dec_rounds(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[], int nr)
{
	//  key pointer
	const uint64_t *kp = (const uint64_t *) rk;

	//  end pointer as loop condition
	const uint64_t *ep = &kp[2 * (nr - 2)];

	uint64_t t0, t1, u0, u1, k0, k1;

	t0 = ((const uint64_t *) ct)[0];		//  get ciphertext
	t1 = ((const uint64_t *) ct)[1];

	k0 = ep[4];								//  last round key
	k1 = ep[5];
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	u0 = saes64_decsm(t0, t1);
	u1 = saes64_decsm(t1, t0);
	k0 = ep[2];
	k1 = ep[3];
	u0 = u0 ^ k0;
	u1 = u1 ^ k1;

	do {

		ep -= 4;

		t0 = saes64_decsm(u0, u1);
		t1 = saes64_decsm(u1, u0);
		k0 = ep[4];
		k1 = ep[5];
		t0 = t0 ^ k0;
		t1 = t1 ^ k1;

		u0 = saes64_decsm(t0, t1);
		u1 = saes64_decsm(t1, t0);
		k0 = ep[2];
		k1 = ep[3];
		u0 = u0 ^ k0;
		u1 = u1 ^ k1;

	} while (kp != ep);

	t0 = saes64_decs(u0, u1);
	t1 = saes64_decs(u1, u0);
	k0 = kp[0];								//  first round key
	k1 = kp[1];
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	((uint64_t *) pt)[0] = t0;				//  store plaintext
	((uint64_t *) pt)[1] = t1;

	return;

}
