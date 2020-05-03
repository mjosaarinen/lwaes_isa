//  rv_endian.h
//  2020-04-30  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  RISC-V specific endianess support would be here (via intrinsics)

#ifndef _RV_ENDIAN_H_
#define _RV_ENDIAN_H_

//  revert if not big endian

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define GREV_BE32(x) (x)
#else
	//  grev(x, 0x18) or rev8
#define GREV_BE32(x) (	\
	(((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8)  | \
	(((x) & 0x0000FF00) << 8)  | (((x) & 0x000000FF) << 24))
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define GREV_BE64(x) (x)
#else
//  RISC-V: grev(x, 0x38) or rev8(x)
#define GREV_BE64(x) (						\
	(((x) & 0xFF00000000000000LL) >> 56) | 	\
	(((x) & 0x00FF000000000000LL) >> 40) | 	\
	(((x) & 0x0000FF0000000000LL) >> 24) | 	\
	(((x) & 0x000000FF00000000LL) >> 8)  | 	\
	(((x) & 0x00000000FF000000LL) << 8)  | 	\
	(((x) & 0x0000000000FF0000LL) << 24) | 	\
	(((x) & 0x000000000000FF00LL) << 40) | 	\
	(((x) & 0x00000000000000FFLL) << 56))
#endif

//  rotate left
static inline uint32_t rol32(uint32_t x, uint32_t n)
{
	return ((x) << n) | ((x) >> (32 - n));
}

//  little-endian loads and stores (unaligned)

static inline uint32_t get32u_le(const uint8_t * v)
{
	return ((uint32_t) v[0]) | (((uint32_t) v[1]) << 8) |
		(((uint32_t) v[2]) << 16) | (((uint32_t) v[3]) << 24);
}

static inline void put32u_le(uint8_t * v, uint32_t x)
{
	v[0] = x;
	v[1] = x >> 8;
	v[2] = x >> 16;
	v[3] = x >> 24;
}

static inline uint64_t get64u_le(const uint8_t * v)
{
	return ((uint64_t) v[0]) | (((uint64_t) v[1]) << 8) |
		(((uint64_t) v[2]) << 16) | (((uint64_t) v[3]) << 24) |
		(((uint64_t) v[4]) << 32) | (((uint64_t) v[5]) << 40) |
		(((uint64_t) v[6]) << 48) | (((uint64_t) v[7]) << 56);
}

static inline void put64u_le(uint8_t * v, uint64_t x)
{
	v[0] = x;
	v[1] = x >> 8;
	v[2] = x >> 16;
	v[3] = x >> 24;
	v[4] = x >> 32;
	v[5] = x >> 40;
	v[6] = x >> 48;
	v[7] = x >> 56;
}


//  big-endian loads and stores (unaligned)

static inline uint32_t get32u_be(const uint8_t * v)
{
	return (((uint32_t) v[0]) << 24) | (((uint32_t) v[1]) << 16) |
		(((uint32_t) v[2]) << 8) | ((uint32_t) v[3]);
}

static inline void put32u_be(uint8_t * v, uint32_t x)
{
	v[0] = x >> 24;
	v[1] = x >> 16;
	v[2] = x >> 8;
	v[3] = x;
}

static inline uint64_t get64u_be(const uint8_t * v)
{
	return (((uint64_t) v[0]) << 56) | (((uint64_t) v[1]) << 48) |
		(((uint64_t) v[2]) << 40) | (((uint64_t) v[3]) << 32) |
		(((uint64_t) v[4]) << 24) | (((uint64_t) v[5]) << 16) |
		(((uint64_t) v[6]) << 8) | ((uint64_t) v[7]);
}

static inline void put64u_be(uint8_t * v, uint64_t x)
{
	v[0] = x >> 56;
	v[1] = x >> 48;
	v[2] = x >> 40;
	v[3] = x >> 32;
	v[4] = x >> 24;
	v[5] = x >> 16;
	v[6] = x >> 8;
	v[7] = x;
}

#endif
