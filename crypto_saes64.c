//  crypto_saes64.c
//  2020-05-03  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Emulation code for SAES64   (XXX need to prettify)

#include "crypto_saes64.h"
#include "crypto_saes32.h"

static inline uint32_t _l_hi32(uint64_t x)
{
	return (uint32_t) (x >> 32);
}

static inline uint32_t _l_lo32(uint64_t x)
{
	return (uint32_t) x;
}

static inline uint64_t _l_to64(uint32_t lo, uint32_t hi)
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

	return _l_to64(u0, u1);
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

	return _l_to64(u0, u1);
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

	return _l_to64(u0, u1);
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

	return _l_to64(u0, u1);
}

uint64_t saes64_imix(uint64_t rs1)
{
	uint32_t t0, t1, x;

	t0 = _l_lo32(rs1);
	t1 = _l_hi32(rs1);

	x = saes32_encs(0, t0, 0);
	x = saes32_encs(x, t0, 1);
	x = saes32_encs(x, t0, 2);
	x = saes32_encs(x, t0, 3);

	t0 = saes32_decsm(0, x, 0);
	t0 = saes32_decsm(t0, x, 1);
	t0 = saes32_decsm(t0, x, 2);
	t0 = saes32_decsm(t0, x, 3);

	x = saes32_encs(0, t1, 0);
	x = saes32_encs(x, t1, 1);
	x = saes32_encs(x, t1, 2);
	x = saes32_encs(x, t1, 3);

	t1 = saes32_decsm(0, x, 0);
	t1 = saes32_decsm(t1, x, 1);
	t1 = saes32_decsm(t1, x, 2);
	t1 = saes32_decsm(t1, x, 3);

	return _l_to64(t0, t1);
}

uint64_t saes64_ks1(uint64_t rs1, uint8_t i)
{
	//  round constants -- just iterations of the xtime() LFSR
	const uint8_t aes_rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
	};
	uint32_t t, u;
	uint32_t rc;

	t = rs1 >> 32;
	rc = 0;

	if (i != 10) {
		t = (t >> 8) | (t << 24);			//  t= ROR(t, 8)
		rc = aes_rcon[i];
	}

	u = saes32_encs(0, t, 0);
	u = saes32_encs(u, t, 1);
	u = saes32_encs(u, t, 2);
	u = saes32_encs(u, t, 3);

	u ^= rc;

	return _l_to64(u, u);
}

uint64_t saes64_ks2(uint64_t rs1, uint64_t rs2)
{
	uint32_t rs1_1 = rs1 >> 32;
	uint32_t rs2_0 = rs2;
	uint32_t rs2_1 = rs2 >> 32;

	return _l_to64(rs1_1 ^ rs2_0, rs1_1 ^ rs2_0 ^ rs2_1);
}
