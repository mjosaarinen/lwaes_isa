//  saes64.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Emulation code for SAES64

#include "saes64.h"
#include "sboxes.h"

//  Multiply by 0x02 in AES's GF(256) - LFSR style

static inline uint8_t aes_xtime(uint8_t x)
{
	return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00);
}

//  encrypt (main rounds)

uint64_t saes64_encs(uint64_t rs1, uint64_t rs2)
{
	return ((uint64_t) aes_sbox[rs1 & 0xFF]) |
		(((uint64_t) aes_sbox[(rs1 >> 40) & 0xFF]) << 8) |
		(((uint64_t) aes_sbox[(rs2 >> 16) & 0xFF]) << 16) |
		(((uint64_t) aes_sbox[(rs2 >> 56) & 0xFF]) << 24) |
		(((uint64_t) aes_sbox[(rs1 >> 32) & 0xFF]) << 32) |
		(((uint64_t) aes_sbox[(rs2 >> 8) & 0xFF]) << 40) |
		(((uint64_t) aes_sbox[(rs2 >> 48) & 0xFF]) << 48) |
		(((uint64_t) aes_sbox[(rs1 >> 24) & 0xFF]) << 56);
}

//  mixcolumns

static inline uint32_t saes64_mc8(uint32_t x)
{
	uint32_t x2;

	x2 = aes_xtime(x);						//  double x
	x = ((x ^ x2) << 24) |					//  0x03    MixCol MDS Matrix
		(x << 16) |							//  0x01
		(x << 8) |							//  0x01
		x2;									//  0x02

	return x;
}

static uint32_t saes64_mc32(uint32_t x)
{
	uint32_t y;

	y = saes64_mc8((x >> 24) & 0xFF);
	y = (y << 8) | (y >> 24);
	y ^= saes64_mc8((x >> 16) & 0xFF);
	y = (y << 8) | (y >> 24);
	y ^= saes64_mc8((x >> 8) & 0xFF);
	y = (y << 8) | (y >> 24);
	y ^= saes64_mc8(x & 0xFF);

	return y;
}

//  encrypt (final round)

uint64_t saes64_encsm(uint64_t rs1, uint64_t rs2)
{
	uint64_t t;

	t = saes64_encs(rs1, rs2);

	return ((uint64_t) saes64_mc32(t)) |
		(((uint64_t) saes64_mc32(t >> 32)) << 32);
}

//  decrypt (main rounds)

uint64_t saes64_decs(uint64_t rs1, uint64_t rs2)
{
	return ((uint64_t) aes_isbox[rs1 & 0xFF]) |
		(((uint64_t) aes_isbox[(rs2 >> 40) & 0xFF]) << 8) |
		(((uint64_t) aes_isbox[(rs2 >> 16) & 0xFF]) << 16) |
		(((uint64_t) aes_isbox[(rs1 >> 56) & 0xFF]) << 24) |
		(((uint64_t) aes_isbox[(rs1 >> 32) & 0xFF]) << 32) |
		(((uint64_t) aes_isbox[(rs1 >> 8) & 0xFF]) << 40) |
		(((uint64_t) aes_isbox[(rs2 >> 48) & 0xFF]) << 48) |
		(((uint64_t) aes_isbox[(rs2 >> 24) & 0xFF]) << 56);
}

//  inverse mixcolumns

static inline uint32_t saes64_imc8(uint32_t x)
{
	uint32_t x2, x4, x8;

	x2 = aes_xtime(x);						//  double x
	x4 = aes_xtime(x2);						//  double to 4*x
	x8 = aes_xtime(x4);						//  double to 8*x

	x = ((x ^ x2 ^ x8) << 24) |				//  0x0B    Inv MixCol MDS Matrix
		((x ^ x4 ^ x8) << 16) |				//  0x0D
		((x ^ x8) << 8) |					//  0x09
		(x2 ^ x4 ^ x8);						//  0x0E

	return x;
}

static uint32_t saes64_imc32(uint32_t x)
{
	uint32_t y;

	y = saes64_imc8((x >> 24) & 0xFF);
	y = (y << 8) | (y >> 24);
	y ^= saes64_imc8((x >> 16) & 0xFF);
	y = (y << 8) | (y >> 24);
	y ^= saes64_imc8((x >> 8) & 0xFF);
	y = (y << 8) | (y >> 24);
	y ^= saes64_imc8(x & 0xFF);

	return y;
}

//  decrypt (final round)

uint64_t saes64_decsm(uint64_t rs1, uint64_t rs2)
{
	return saes64_imix(saes64_decs(rs1, rs2));
}

//  key schedule (inverse mixcolumns for decryption keys)

uint64_t saes64_imix(uint64_t rs1)
{
	return ((uint64_t) saes64_imc32(rs1)) |
		(((uint64_t) saes64_imc32(rs1 >> 32)) << 32);
}

//  key schedule 1

uint64_t saes64_ks1(uint64_t rs1, uint8_t i)
{
	uint32_t t, rc;

	t = rs1 >> 32;
	rc = 0;

	if (i != 10) {
		t = (t >> 8) | (t << 24);			//  t = ROR(t, 8)
		rc = aes_rcon[i];					//  round constant
	}
	//  subword
	t = ((uint32_t) aes_sbox[t & 0xFF]) |
		(((uint32_t) aes_sbox[(t >> 8) & 0xFF]) << 8) |
		(((uint32_t) aes_sbox[(t >> 16) & 0xFF]) << 16) |
		(((uint32_t) aes_sbox[(t >> 24) & 0xFF]) << 24);

	t ^= rc;

	return ((uint64_t) t) | (((uint64_t) t) << 32);
}

//  key schedule 2

uint64_t saes64_ks2(uint64_t rs1, uint64_t rs2)
{
	uint32_t t;

	t = (rs1 >> 32) ^ (rs2 & 0xFFFFFFFF);	//  32 bits

	return ((uint64_t) t) ^					//  low 32 bits
		(((uint64_t) t) << 32) ^ (rs2 & 0xFFFFFFFF00000000LL);
}
