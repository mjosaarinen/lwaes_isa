//  bitmanip.c
//  2020-03-07  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  instruction emulation code -- these are all from bitmanip

#include "bitmanip.h"

//  carryless multiply

uint32_t rv32b_clmul(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = 0;
	for (int i = 0; i < 32; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 << i;
	return x;
}

uint32_t rv32b_clmulh(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = 0;
	for (int i = 1; i < 32; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 >> (32 - i);
	return x;
}

uint32_t rv32b_clmulr(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = 0;
	for (int i = 0; i < 32; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 >> (32 - i - 1);
	return x;
}

//	64-bit

uint64_t rv64b_clmul(uint64_t rs1, uint64_t rs2)
{
	uint64_t x = 0;
	for (int i = 0; i < 64; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 << i;
	return x;
}

uint64_t rv64b_clmulh(uint64_t rs1, uint64_t rs2)
{
	uint64_t x = 0;
	for (int i = 1; i < 64; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 >> (64 - i);
	return x;
}

uint64_t rv64b_clmulr(uint64_t rs1, uint64_t rs2)
{
	uint64_t x = 0;
	for (int i = 0; i < 64; i++)
		if ((rs2 >> i) & 1)
			x ^= rs1 >> (64 - i - 1);
	return x;
}

//  rotate right ROR / RORI

uint32_t rv32b_ror(uint32_t rs1, uint32_t rs2)
{
	int shamt = rs2 & (32 - 1);
	return (rs1 >> shamt) | (rs1 << ((32 - shamt) & (32 - 1)));
}

uint64_t rv64b_ror(uint64_t rs1, uint64_t rs2)
{
	int shamt = rs2 & (64 - 1);
	return (rs1 >> shamt) | (rs1 << ((64 - shamt) & (64 - 1)));
}

//  and with negate ANDN

uint64_t rv32b_andn(uint32_t rs1, uint32_t rs2)
{
	return rs1 & ~rs2;
}

uint64_t rv64b_andn(uint64_t rs1, uint64_t rs2)
{
	return rs1 & ~rs2;
}

//  generalized reverse GREV / GREVI

uint32_t rv32b_grev(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 31;
	if (shamt & 1)
		x = ((x & 0x55555555) << 1) | ((x & 0xAAAAAAAA) >> 1);
	if (shamt & 2)
		x = ((x & 0x33333333) << 2) | ((x & 0xCCCCCCCC) >> 2);
	if (shamt & 4)
		x = ((x & 0x0F0F0F0F) << 4) | ((x & 0xF0F0F0F0) >> 4);
	if (shamt & 8)
		x = ((x & 0x00FF00FF) << 8) | ((x & 0xFF00FF00) >> 8);
	if (shamt & 16)
		x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16);
	return x;
}

uint64_t rv64b_grev(uint64_t rs1, uint64_t rs2)
{
	uint64_t x = rs1;
	int shamt = rs2 & 63;
	if (shamt & 1)
		x = ((x & 0x5555555555555555LL) << 1) |
			((x & 0xAAAAAAAAAAAAAAAALL) >> 1);
	if (shamt & 2)
		x = ((x & 0x3333333333333333LL) << 2) |
			((x & 0xCCCCCCCCCCCCCCCCLL) >> 2);
	if (shamt & 4)
		x = ((x & 0x0F0F0F0F0F0F0F0FLL) << 4) |
			((x & 0xF0F0F0F0F0F0F0F0LL) >> 4);
	if (shamt & 8)
		x = ((x & 0x00FF00FF00FF00FFLL) << 8) |
			((x & 0xFF00FF00FF00FF00LL) >> 8);
	if (shamt & 16)
		x = ((x & 0x0000FFFF0000FFFFLL) << 16) |
			((x & 0xFFFF0000FFFF0000LL) >> 16);
	if (shamt & 32)
		x = ((x & 0x00000000FFFFFFFFLL) << 32) |
			((x & 0xFFFFFFFF00000000LL) >> 32);
	return x;
}

//  32-bit helper for SHFL/UNSHFL

static inline uint32_t shuffle32_stage(uint32_t src, uint32_t ml,
									   uint32_t mr, int n)
{
	uint32_t x = src & ~(ml | mr);
	x |= ((src << n) & ml) | ((src >> n) & mr);
	return x;
}

//  generalized shuffle SHFL / SHFLI

uint32_t rv32b_shfl(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 8)
		x = shuffle32_stage(x, 0x00FF0000, 0x0000FF00, 8);
	if (shamt & 4)
		x = shuffle32_stage(x, 0x0F000F00, 0x00F000F0, 4);
	if (shamt & 2)
		x = shuffle32_stage(x, 0x30303030, 0x0C0C0C0C, 2);
	if (shamt & 1)
		x = shuffle32_stage(x, 0x44444444, 0x22222222, 1);

	return x;
}

//  generalized unshuffle UNSHFL / UNSHFLI

uint32_t rv32b_unshfl(uint32_t rs1, uint32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 1)
		x = shuffle32_stage(x, 0x44444444, 0x22222222, 1);
	if (shamt & 2)
		x = shuffle32_stage(x, 0x30303030, 0x0C0C0C0C, 2);
	if (shamt & 4)
		x = shuffle32_stage(x, 0x0F000F00, 0x00F000F0, 4);
	if (shamt & 8)
		x = shuffle32_stage(x, 0x00FF0000, 0x0000FF00, 8);

	return x;
}


//  64-bit helper for SHFLW/UNSHFLW

static inline uint64_t shuffle64_stage(uint64_t src, uint64_t ml,
									   uint64_t mr, int n)
{
	uint64_t x = src & ~(ml | mr);
	x |= ((src << n) & ml) | ((src >> n) & mr);
	return x;
}

//  generalized shuffle SHFLW

uint64_t rv64b_shfl(uint64_t rs1, uint64_t rs2)
{
	uint64_t x = rs1;
	int shamt = rs2 & 31;

	if (shamt & 16)
		x = shuffle64_stage(x, 0x0000FFFF00000000LL, 0x00000000FFFF0000LL, 16);
	if (shamt & 8)
		x = shuffle64_stage(x, 0x00FF000000FF0000LL, 0x0000FF000000FF00LL, 8);
	if (shamt & 4)
		x = shuffle64_stage(x, 0x0F000F000F000F00LL, 0x00F000F000F000F0LL, 4);
	if (shamt & 2)
		x = shuffle64_stage(x, 0x3030303030303030LL, 0x0C0C0C0C0C0C0C0CLL, 2);
	if (shamt & 1)
		x = shuffle64_stage(x, 0x4444444444444444LL, 0x2222222222222222LL, 1);

	return x;
}

//  generalized unshuffle UNSHFLW

uint64_t rv64b_unshfl(uint64_t rs1, uint64_t rs2)
{
	uint64_t x = rs1;
	int shamt = rs2 & 31;

	if (shamt & 1)
		x = shuffle64_stage(x, 0x4444444444444444LL, 0x2222222222222222LL, 1);
	if (shamt & 2)
		x = shuffle64_stage(x, 0x3030303030303030LL, 0x0C0C0C0C0C0C0C0CLL, 2);
	if (shamt & 4)
		x = shuffle64_stage(x, 0x0F000F000F000F00LL, 0x00F000F000F000F0LL, 4);
	if (shamt & 8)
		x = shuffle64_stage(x, 0x00FF000000FF0000LL, 0x0000FF000000FF00LL, 8);
	if (shamt & 16)
		x = shuffle64_stage(x, 0x0000FFFF00000000LL, 0x00000000FFFF0000LL, 16);

	return x;
}
