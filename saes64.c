//  saes64.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Emulation code for SAES64

#include "saes64.h"
#include "sboxes.h"

//  ( Multiply by 0x02 in AES's GF(256) - LFSR style )

static inline uint8_t aes_xtime(uint8_t x)
{
	return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00);
}

//  ( MixColumns functions )

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

//  SAES64.ENCS:    Half of ShiftRows and SubBytes (last round)

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

//  SAES64.ENCSM:   Half of ShiftRows, SubBytes, and MixColumns

uint64_t saes64_encsm(uint64_t rs1, uint64_t rs2)
{
	uint64_t x;

	//  ShiftRows and SubBytes
	x = saes64_encs(rs1, rs2);

	//  MixColumns
	x = ((uint64_t) saes64_mc32(x)) |
		(((uint64_t) saes64_mc32(x >> 32)) << 32);

	return x;
}

//  SAES64.DECS:    Half of Inverse ShiftRows and SubBytes (last round)

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

//  SAES64.DECSM:   Half of Inverse ShiftRows, SubBytes, and MixColumns

uint64_t saes64_decsm(uint64_t rs1, uint64_t rs2)
{
	uint64_t x;

	x = saes64_decs(rs1, rs2);				//  Inverse ShiftRows, SubBytes
	x = saes64_imix(x);						//  Inverse MixColumns  

	return x;
}

//  ( Inverse MixColumns functions )

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

//  SAES64.IMIX:    Inverse MixColumns for decryption key schedule

uint64_t saes64_imix(uint64_t rs1)
{
	return ((uint64_t) saes64_imc32(rs1)) |
		(((uint64_t) saes64_imc32(rs1 >> 32)) << 32);
}

//  SAES.KS1:       Key Schedule 1 -- SubWord and opt. rotation, round const

uint64_t saes64_ks1(uint64_t rs1, uint8_t i)
{
	uint32_t t, rc;

	t = rs1 >> 32;
	rc = 0;

	if (i < 10) {							//  10: don't do it
		t = (t >> 8) | (t << 24);			//  t = ROR(t, 8)
		rc = aes_rcon[i];					//  round constant
	}
	//  SubWord
	t = ((uint32_t) aes_sbox[t & 0xFF]) |
		(((uint32_t) aes_sbox[(t >> 8) & 0xFF]) << 8) |
		(((uint32_t) aes_sbox[(t >> 16) & 0xFF]) << 16) |
		(((uint32_t) aes_sbox[(t >> 24) & 0xFF]) << 24);

	t ^= rc;

	return ((uint64_t) t) | (((uint64_t) t) << 32);
}

//  SAES.KS2:       Key Schedule 2 -- Linear expansion

uint64_t saes64_ks2(uint64_t rs1, uint64_t rs2)
{
	uint32_t t;

	t = (rs1 >> 32) ^ (rs2 & 0xFFFFFFFF);	//  32 bits

	return ((uint64_t) t) ^					//  low 32 bits
		(((uint64_t) t) << 32) ^ (rs2 & 0xFFFFFFFF00000000LL);
}
