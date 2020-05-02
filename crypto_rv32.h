//  crypto_rv32.h
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES32

#ifndef _CRYPTO_RV32_H_
#define _CRYPTO_RV32_H_

#include <stdint.h>

//  Function codes -- see crypto_saes32.c

#define SAES32_ENCSM	0
#define SAES32_ENCS		1
#define SAES32_DECSM	2
#define SAES32_DECS		3
#define SSM4_ED			4
#define SSM4_KS			5

//  SAES32: Instruction for a byte select, single S-box, and linear operation.

uint32_t saes32(uint32_t rs1, uint32_t rs2, int sn);

//  Pseudo-ops defined in the spec

static inline uint32_t saes32_encsm(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_ENCSM << 2) | bs);
}

static inline uint32_t saes32_encs(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_ENCS << 2) | bs);
}

static inline uint32_t saes32_decsm(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_DECSM << 2) | bs);
}

static inline uint32_t saes32_decs(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SAES32_DECS << 2) | bs);
}

static inline uint32_t ssm4_ed(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SSM4_ED << 2) | bs);
}

static inline uint32_t ssm4_ks(uint32_t rs1, uint32_t rs2, int bs)
{
	return saes32(rs1, rs2, (SSM4_KS << 2) | bs);
}

#endif										//  _CRYPTO_RV32_H_
