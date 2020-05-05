//  saes32.c
//  2020-01-24  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Running pseudocode for SAES32 (and ENC4S) AES/SM4 instruction.

#include "saes32.h"
#include "sboxes.h"

//  Function codes

#define SAES32_ENCSM	0
#define SAES32_ENCS		1
#define SAES32_DECSM	2
#define SAES32_DECS		3
#define SSM4_ED			4
#define SSM4_KS			5

//  Multiply by 0x02 in AES's GF(256) - LFSR style

static inline uint8_t aes_xtime(uint8_t x)
{
	return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00);
}

//  === THIS IS THE SINGLE LIGHTWEIGHT INSTRUCTION FOR AES AND SM4  ===

//  SAES32: Instruction for a byte select, single S-box, and linear operation.

uint32_t saes32(uint32_t rs1, uint32_t rs2, int fn)
{
	uint32_t fa, fb, x, x2, x4, x8;

	fa = 8 * (fn & 3);						//  [1:0]   byte select / rotate
	fb = (fn >> 2) & 7;						//  [4:2]   cipher select

	//  select input byte

	x = (rs2 >> fa) & 0xFF;					//  select byte

	//  8->8 bit s-box

	switch (fb) {

	case SAES32_ENCSM:						//  0 : AES Forward + MC
	case SAES32_ENCS:						//  1 : AES Forward "key"
		x = aes_sbox[x];
		break;

	case SAES32_DECSM:						//  1 : AES Inverse + MC
	case SAES32_DECS:						//  2 : AES Inverse "key"
		x = aes_isbox[x];
		break;

	case SSM4_ED:							//  3 : SM4 encrypt/decrypt
	case SSM4_KS:							//  4 : SM4 key schedule
		x = sm4_sbox[x];
		break;

	default:								//  none
		break;
	}

	//  8->32 bit linear transforms expressed as little-endian

	switch (fb) {

	case SAES32_ENCSM:						//  0 : AES Forward MixCol
		x2 = aes_xtime(x);					//  double x
		x = ((x ^ x2) << 24) |				//  0x03    MixCol MDS Matrix
			(x << 16) |						//  0x01
			(x << 8) |						//  0x01
			x2;								//  0x02
		break;

	case SAES32_DECSM:						//  2 : AES Inverse MixCol
//    ( case 6:     //  6 : AES Inverse MixCol *only* )
		x2 = aes_xtime(x);					//  double x
		x4 = aes_xtime(x2);					//  double to 4*x
		x8 = aes_xtime(x4);					//  double to 8*x
		x = ((x ^ x2 ^ x8) << 24) |			//  0x0B    Inv MixCol MDS Matrix
			((x ^ x4 ^ x8) << 16) |			//  0x0D
			((x ^ x8) << 8) |				//  0x09
			(x2 ^ x4 ^ x8);					//  0x0E
		break;

	case SSM4_ED:							//  4 : SM4 linear transform L 
		x = x ^ (x << 8) ^ (x << 2) ^ (x << 18) ^
			((x & 0x3F) << 26) ^ ((x & 0xC0) << 10);
		break;

	case SSM4_KS:							//  5 : SM4 transform L' (key)
		x = x ^ ((x & 0x07) << 29) ^ ((x & 0xFE) << 7) ^
			((x & 1) << 23) ^ ((x & 0xF8) << 13);
		break;

	default:								//  none
		break;

	}

	//  rotate output left by fa bits

	if (fa != 0) {
		x = (x << fa) | (x >> (32 - fa));
	}

	return x ^ rs1;							//  XOR with rs2
}

//  === PSEUDO OPS ===

//  AES Encryption

uint32_t saes32_encsm(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_ENCSM << 2) | bs);
}

uint32_t saes32_encs(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_ENCS << 2) | bs);
}

//  AES Decryption

uint32_t saes32_decsm(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_DECSM << 2) | bs);
}

uint32_t saes32_decs(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_DECS << 2) | bs);
}

//  SM4 Encryption, Decryption and Key Schedule

uint32_t ssm4_ed(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SSM4_ED << 2) | bs);
}

uint32_t ssm4_ks(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SSM4_KS << 2) | bs);
}
