//  ghash.h
//  2020-03-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  a minimal interface to core GHASH finite field operations

#ifndef _GHASH_H_
#define _GHASH_H_

#include <stdint.h>

//  A GF(2^128) element type -- just for alignment and to avoid casts

typedef union {
	uint8_t b[16];
	uint32_t w[4];
	uint64_t d[2];
} gf128_t;

//  Function pointers so that different versions can be tested: in aes_gcm.c

//  reverse bits in bytes of a 128-bit block; do this for h and final value
extern void (*ghash_rev)(gf128_t * z);

//  finitie field multiply z = ( z ^ rev(x) ) * h
extern void (*ghash_mul)(gf128_t * z, const gf128_t * x, const gf128_t * h);

//  32-bit variants: rv32_ghash.c
void rv32_ghash_rev(gf128_t * z);
void rv32_ghash_mul(gf128_t * z, const gf128_t * x, const gf128_t * h);

//  64-bit variants: rv64_ghash.c
void rv64_ghash_rev(gf128_t * z);
void rv64_ghash_mul(gf128_t * z, const gf128_t * x, const gf128_t * h);

#endif										/* _GHASH_H_ */
