//  crypto_saes64.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

#include "crypto_rv32.h"

static inline uint32_t _l_hi32(uint64_t x)
{
	return (uint32_t) (x >> 32);
}

static inline uint32_t _l_lo32(uint64_t x)
{
	return (uint32_t) x;
}

static inline uint64_t _l_lo64(uint32_t lo, uint32_t hi)
{
	return ((uint64_t) lo) | (((uint64_t) hi) << 32);
}

uint64_t saes64_encsm(uint64_t rs1, uint64_t rs2)
{
	uint32_t t0, t1, t2, t3;
	uint32_t u0, u1;

	t0 = _l_lo32(rs1);
	t1 = _l_hi32(rs1);
	t2 = _l_lo32(rs2);
	t3 = _l_hi32(rs2);

	u0 = saes32_encsm(0, t0, 0);
	u0 = saes32_encsm(u0, t1, 1);
	u0 = saes32_encsm(u0, t2, 2);
	u0 = saes32_encsm(u0, t3, 3);

	u1 = saes32_encsm(0, t1, 0);
	u1 = saes32_encsm(u1, t2, 1);
	u1 = saes32_encsm(u1, t3, 2);
	u1 = saes32_encsm(u1, t0, 3);

	return _l_lo64(u0, u1);
}

uint64_t saes64_encs(uint64_t rs1, uint64_t rs2)
{
	uint32_t t0, t1, t2, t3;
	uint32_t u0, u1;

	t0 = _l_lo32(rs1);
	t1 = _l_hi32(rs1);
	t2 = _l_lo32(rs2);
	t3 = _l_hi32(rs2);

	u0 = saes32_encs(0, t0, 0);
	u0 = saes32_encs(u0, t1, 1);
	u0 = saes32_encs(u0, t2, 2);
	u0 = saes32_encs(u0, t3, 3);

	u1 = saes32_encs(0, t1, 0);
	u1 = saes32_encs(u1, t2, 1);
	u1 = saes32_encs(u1, t3, 2);
	u1 = saes32_encs(u1, t0, 3);

	return _l_lo64(u0, u1);
}

uint64_t saes64_decsm(uint64_t rs1, uint64_t rs2)
{
	uint32_t t0, t1, t2, t3;
	uint32_t u0, u1;

	t0 = _l_lo32(rs1);
	t1 = _l_hi32(rs1);
	t2 = _l_lo32(rs2);
	t3 = _l_hi32(rs2);

	u0 = saes32_decsm(0, t0, 0);
	u0 = saes32_decsm(u0, t3, 1);
	u0 = saes32_decsm(u0, t2, 2);
	u0 = saes32_decsm(u0, t1, 3);

	u1 = saes32_decsm(0, t1, 0);
	u1 = saes32_decsm(u1, t0, 1);
	u1 = saes32_decsm(u1, t3, 2);
	u1 = saes32_decsm(u1, t2, 3);

	return _l_lo64(u0, u1);
}

uint64_t saes64_decs(uint64_t rs1, uint64_t rs2)
{
	uint32_t t0, t1, t2, t3;
	uint32_t u0, u1;

	t0 = _l_lo32(rs1);
	t1 = _l_hi32(rs1);
	t2 = _l_lo32(rs2);
	t3 = _l_hi32(rs2);

	u0 = saes32_decs(0, t0, 0);
	u0 = saes32_decs(u0, t3, 1);
	u0 = saes32_decs(u0, t2, 2);
	u0 = saes32_decs(u0, t1, 3);

	u1 = saes32_decs(0, t1, 0);
	u1 = saes32_decs(u1, t0, 1);
	u1 = saes32_decs(u1, t3, 2);
	u1 = saes32_decs(u1, t2, 3);

	return _l_lo64(u0, u1);
}
