//  aes_otf_saes64.c
//  2020-05-06  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  AES Encryption with on-the-fly key expansion

#include <stddef.h>

#include "aes_wrap.h"
#include "saes64.h"

//  === AES-128 round with on-the-fly key schedule ===

//  2 x SAES64.ENCS[M], 1 x SAES64.KS1, 2 x SAES64.KS2, 2 x XOR

#define SAES64_OTF128A(i) {		\
	u0 = saes64_encsm(t0, t1);	\
	u1 = saes64_encsm(t1, t0);	\
	ks = saes64_ks1(k1, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1); 	\
	u0 = u0 ^ k0;				\
	u1 = u1 ^ k1;				}

#define SAES64_OTF128B(i) {		\
	t0 = saes64_encsm(u0, u1);	\
	t1 = saes64_encsm(u1, u0);	\
	ks = saes64_ks1(k1, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1); 	\
	t0 = t0 ^ k0;				\
	t1 = t1 ^ k1;				}

void aes128_enc_otf_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t * rk)
{
	uint64_t t0, t1, u0, u1, k0, k1, ks;

	k0 = ((const uint64_t *) rk)[0];		//  load key
	k1 = ((const uint64_t *) rk)[1];

	t0 = ((const uint64_t *) pt)[0];		//  get plaintext
	t1 = ((const uint64_t *) pt)[1];

	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	SAES64_OTF128A(0);						//  first round
	SAES64_OTF128B(1);						//  # 2
	SAES64_OTF128A(2);						//  # 3
	SAES64_OTF128B(3);						//  # 4
	SAES64_OTF128A(4);						//  # 5
	SAES64_OTF128B(5);						//  # 6
	SAES64_OTF128A(6);						//  # 7
	SAES64_OTF128B(7);						//  # 8
	SAES64_OTF128A(8);						//  # 9
	t0 = saes64_encs(u0, u1);				//  last round
	t1 = saes64_encs(u1, u0);
	ks = saes64_ks1(k1, 9);
	k0 = saes64_ks2(ks, k0);
	k1 = saes64_ks2(k0, k1);
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	((uint64_t *) ct)[0] = t0;				//  store ciphertext
	((uint64_t *) ct)[1] = t1;
}

//  === AES-192 round with on-the-fly key schedule ===

//  3 rounds has: 2 x SAES64.KS1, 6 x SAES64.KS2, 6 x AES64.ENCSM, 6 x XOR

#define SAES64_OTF192K(i) {		\
	ks = saes64_ks1(k2, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1);	\
	k2 = saes64_ks2(k1, k2); 	}

#define SAES64_OTF192A {		\
	t0 = t0 ^ k0;				\
	t1 = t1 ^ k1;				\
	u0 = saes64_encsm(t0, t1);	\
	u1 = saes64_encsm(t1, t0);	}

#define SAES64_OTF192B(i) {		\
	u0 = u0 ^ k2;				\
	SAES64_OTF192K(i);			\
	u1 = u1 ^ k0;				\
	v0 = saes64_encsm(u0, u1);	\
	v1 = saes64_encsm(u1, u0);	}

#define SAES64_OTF192C(i) {		\
	v0 = v0 ^ k1;				\
	v1 = v1 ^ k2;				\
	SAES64_OTF192K(i);			\
	t0 = saes64_encsm(v0, v1);	\
	t1 = saes64_encsm(v1, v0);	}

void aes192_enc_otf_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t * rk)
{
	uint64_t t0, t1, u0, u1, v0, v1, k0, k1, k2, ks;

	k0 = ((const uint64_t *) rk)[0];		//  load key
	k1 = ((const uint64_t *) rk)[1];
	k2 = ((const uint64_t *) rk)[2];

	t0 = ((const uint64_t *) pt)[0];		//  get plaintext
	t1 = ((const uint64_t *) pt)[1];

	SAES64_OTF192A;							//  first round
	SAES64_OTF192B(0);						//  # 2
	SAES64_OTF192C(1);						//  # 3
	SAES64_OTF192A;							//  # 4
	SAES64_OTF192B(2);						//  # 5
	SAES64_OTF192C(3);						//  # 6
	SAES64_OTF192A;							//  # 7
	SAES64_OTF192B(4);						//  # 8
	SAES64_OTF192C(5);						//  # 9
	SAES64_OTF192A;							//  # 10
	SAES64_OTF192B(6);						//  # 11

	v0 = v0 ^ k1;							//  last round
	v1 = v1 ^ k2;
	ks = saes64_ks1(k2, 7);					//  different because ..
	k0 = saes64_ks2(ks, k0);
	k1 = saes64_ks2(k0, k1);				//  .. no need to compute k2
	t0 = saes64_encs(v0, v1);				//  different function
	t1 = saes64_encs(v1, v0);
	t0 = t0 ^ k0;							//  final AddRoundKey
	t1 = t1 ^ k1;

	((uint64_t *) ct)[0] = t0;				//  store ciphertext
	((uint64_t *) ct)[1] = t1;
}


//  === AES-256 round with on-the-fly key schedule ===

//  2 x saes64_encs[m], 1 x saes64_KS1, 2 x SAES64.KS2, 2 x XOR

#define SAES64_OTF256A(i) {		\
	u0 = saes64_encsm(t0, t1);	\
	u1 = saes64_encsm(t1, t0);	\
	ks = saes64_ks1(k3, i);		\
	k0 = saes64_ks2(ks, k0);	\
	k1 = saes64_ks2(k0, k1);	\
	u0 = u0 ^ k2;				\
	u1 = u1 ^ k3;				}

#define SAES64_OTF256B(i) {		\
	t0 = saes64_encsm(u0, u1);	\
	t1 = saes64_encsm(u1, u0);	\
	ks = saes64_ks1(k1, i);		\
	k2 = saes64_ks2(ks, k2);	\
	k3 = saes64_ks2(k2, k3); 	\
	t0 = t0 ^ k0;				\
	t1 = t1 ^ k1;				}


void aes256_enc_otf_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t * rk)
{
	uint64_t t0, t1, u0, u1, k0, k1, k2, k3, ks;

	k0 = ((const uint64_t *) rk)[0];		//  load key
	k1 = ((const uint64_t *) rk)[1];
	k2 = ((const uint64_t *) rk)[2];
	k3 = ((const uint64_t *) rk)[3];

	t0 = ((const uint64_t *) pt)[0];		//  get plaintext
	t1 = ((const uint64_t *) pt)[1];

	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	SAES64_OTF256A(0);						//  first round
	SAES64_OTF256B(10);						//  # 2
	SAES64_OTF256A(1);						//  # 3
	SAES64_OTF256B(10);						//  # 4
	SAES64_OTF256A(2);						//  # 5
	SAES64_OTF256B(10);						//  # 6
	SAES64_OTF256A(3);						//  # 7
	SAES64_OTF256B(10);						//  # 8
	SAES64_OTF256A(4);						//  # 9
	SAES64_OTF256B(10);						//  # 10
	SAES64_OTF256A(5);						//  # 11
	SAES64_OTF256B(10);						//  # 12
	SAES64_OTF256A(6);						//  # 13
	t0 = saes64_encs(u0, u1);				//  last round
	t1 = saes64_encs(u1, u0);
	t0 = t0 ^ k0;
	t1 = t1 ^ k1;

	((uint64_t *) ct)[0] = t0;				//  store ciphertext
	((uint64_t *) ct)[1] = t1;
}
