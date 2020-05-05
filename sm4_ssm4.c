//  sm4_ssm4.c
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  SM4 (Chinese Encryption Standard) Encryption and Decryption.

#include "sm4_wrap.h"
#include "saes32.h"
#include "rv_endian.h"

//  SSM4_ED_X4  is a block of four ssm4.ed instructions:

#define SSM4_ED_X4(rs1, rs2) {		\
	rs1 = ssm4_ed(rs1, rs2, 0);		\
	rs1 = ssm4_ed(rs1, rs2, 1);		\
	rs1 = ssm4_ed(rs1, rs2, 2);		\
	rs1 = ssm4_ed(rs1, rs2, 3);		\
}

//  SSM4_KS_X4  is a block of four ssm4.ks instructions:

#define SSM4_KS_X4(rs1, rs2) {		\
	rs1 = ssm4_ks(rs1, rs2, 0);		\
	rs1 = ssm4_ks(rs1, rs2, 1);		\
	rs1 = ssm4_ks(rs1, rs2, 2);		\
	rs1 = ssm4_ks(rs1, rs2, 3);		\
}

//  encrypt or decrypt a block, depending on round key ordering

void sm4_encdec(uint8_t out[16], const uint8_t in[16],
				const uint32_t rk[SM4_RK_WORDS])
{
	uint32_t x0, x1, x2, x3, t, u;
	const uint32_t *kp = &rk[SM4_RK_WORDS];

	x0 = get32u_le(in);						//  little endian (native)
	x1 = get32u_le(in + 4);
	x2 = get32u_le(in + 8);
	x3 = get32u_le(in + 12);

	do {

		u = x2 ^ x3;						//  10 XORs total per round

		t = rk[0];							//  subkeys can be inline
		t ^= u;
		t ^= x1;
		SSM4_ED_X4(x0, t);					//  4 x SSM4.ED

		t = rk[1];
		t ^= u;
		t ^= x0;
		SSM4_ED_X4(x1, t);					//  4 x SSM4.ED
		u = x0 ^ x1;

		t = rk[2];
		t ^= u;
		t ^= x3;
		SSM4_ED_X4(x2, t);					//  4 x SSM4.ED

		t = rk[3];
		t ^= u;
		t ^= x2;
		SSM4_ED_X4(x3, t);					//  4 x SSM4.ED

		rk += 4;							//  unroll?

	} while (rk != kp);

	put32u_le(out, x3);
	put32u_le(out + 4, x2);
	put32u_le(out + 8, x1);
	put32u_le(out + 12, x0);
}

//  set key for encryption

void sm4_enc_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
	const uint32_t *kp = &rk[SM4_RK_WORDS];
	uint32_t x0, x1, x2, x3;
	uint32_t t, u, ck;

	x0 = get32u_le(key);					//  fetch key words
	x1 = get32u_le(key + 4);
	x2 = get32u_le(key + 8);
	x3 = get32u_le(key + 12);

	x0 ^= 0xC6BAB1A3;						//  "FK" constants, little-endian
	x1 ^= 0x5033AA56;						//  (note: seems pointless?)
	x2 ^= 0x97917D67;
	x3 ^= 0xDC2270B2;

	ck = 0x140E0600;						//  0x150E0700 with LSBs masked

	do {
/*
	"CK" Discussion:

	The SM4 "CK" round constants are a sequence of bytes 7*i (mod 256) with
	i = 0..127, interpreted as 32-bit words. Often these words are stored in
	a constant table. However many ISAs have a "SIMD" addition that adds 4 or
	more bytes in parallel, which is faster than a table look-up. Even some
	low-ended embedded targets such as Cortex M4 (Armv7E-M/DSP) support this
	(SADD8) and its introduction as a RISC-V extension should be considered.
	Meanwhile, we can perfom the same function with three simple arithmetic
	ops which is likely to still be faster than fetching from a table and
	(with the address arithmatic). This implementation is certainly smaller.
*/
		t = ck ^ 0x01000100;				//  these constants in registers
		ck += 0x1C1C1C1C;					//  if we have "SADD8", then
		ck &= 0xFEFEFEFE;					//  -> 4 x "SADD8" per round.

		u = x2 ^ x3;						//  10 XORs per round
		t = t ^ u;
		t = t ^ x1;
		SSM4_KS_X4(x0, t);					//  4 x SSM4.KS

		rk[0] = x0;							//  four stores per round

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		t = t ^ u;
		t = t ^ x0;
		SSM4_KS_X4(x1, t);					//  4 x SSM4.KS
		rk[1] = x1;

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		u = x0 ^ x1;
		t ^= u;
		t ^= x3;
		SSM4_KS_X4(x2, t);					//  4 x SSM4.KS
		rk[2] = x2;

		t = ck ^ 0x01000100;
		ck += 0x1C1C1C1C;
		ck &= 0xFEFEFEFE;

		t ^= u;
		t ^= x2;
		SSM4_KS_X4(x3, t);					//  4 x SSM4.KS
		rk[3] = x3;

		rk += 4;

	} while (rk != kp);
}

//  set key for decryption

void sm4_dec_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16])
{
	uint32_t t;
	int i, j;

	sm4_enc_key(rk, key);					//  encryption expansion

	//  decryption round keys = encryption round keys in reverse order
	for (i = 0, j = SM4_RK_WORDS - 1; i < j; i++, j--) {
		t = rk[i];
		rk[i] = rk[j];
		rk[j] = t;
	}
}
