//  crypto_rv64.h
//  2020-05-02  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES64

#ifndef _CRYPTO_RV64_H_
#define _CRYPTO_RV64_H_

#include "crypto_rv32.h"

//	XXX WORK IN PROGRESS

static inline  uint32_t hi32(uint64_t x) 
{
	return (uint32_t) (x >> 32);
}

static inline uint32_t lo32(uint64_t x) 
{
	return (uint32_t) x;
}

static inline  uint64_t to64(uint32_t lo, uint32_t hi) 
{
	return ((uint64_t) lo) | (((uint64_t) hi) << 32);
}

static uint64_t saes64_encsm(uint64_t rs1, uint64_t rs2)
{
	uint32_t t0, t1, t2, t3;
	uint32_t u0, u1;

	t0 = lo32(rs1);
	t1 = hi32(rs1);
	t2 = lo32(rs2);
	t3 = hi32(rs2);

	u0 = saes32_encsm(0,  t0, 0);
	u0 = saes32_encsm(u0, t1, 1);
	u0 = saes32_encsm(u0, t2, 2);
	u0 = saes32_encsm(u0, t3, 3);

	u1 = saes32_encsm(0,  t1, 0);
	u1 = saes32_encsm(u1, t2, 1);
	u1 = saes32_encsm(u1, t3, 2);
	u1 = saes32_encsm(u1, t0, 3);

	return to64(u0, u1);
}

static uint64_t saes64_encs(uint64_t rs1, uint64_t rs2)
{
	uint32_t t0, t1, t2, t3;
	uint32_t u0, u1;

	t0 = lo32(rs1);
	t1 = hi32(rs1);
	t2 = lo32(rs2);
	t3 = hi32(rs2);

	u0 = saes32_encs(0,  t0, 0);
	u0 = saes32_encs(u0, t1, 1);
	u0 = saes32_encs(u0, t2, 2);
	u0 = saes32_encs(u0, t3, 3);

	u1 = saes32_encs(0,  t1, 0);
	u1 = saes32_encs(u1, t2, 1);
	u1 = saes32_encs(u1, t3, 2);
	u1 = saes32_encs(u1, t0, 3);

	return to64(u0, u1);
}

#endif
