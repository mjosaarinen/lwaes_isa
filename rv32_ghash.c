//  rv32_ghash.c
//  2020-03-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  32-bit GHASH bit-reverse and multiplication for GCM

#include "ghash.h"
#include "bitmanip.h"

#include <stdio.h>
#include <string.h>

//  disable shift reduction
//#define NO_SHIFTRED
//  disable karatsuba multiplication
//#define NO_KARATSUBA

//  reverse bits in bytes of a 128-bit block; do this for h and final value

void rv32_ghash_rev(gf128_t * z)
{
	z->w[0] = rvb_grev(z->w[0], 7);
	z->w[1] = rvb_grev(z->w[1], 7);
	z->w[2] = rvb_grev(z->w[2], 7);
	z->w[3] = rvb_grev(z->w[3], 7);
}

/*
void mul2(uint64_t *ab0, uint64_t *ab1, uint64_t a, uint64_t b)
{
	uint32_t a0, a1, b0, b1;
	uint32_t x0, x1, x2, x3;
	uint32_t t0, t1, t2;

	a0 = a;
	a1 = a >> 32;
	b0 = b;
	b1 = b >> 32;

	x3 = rvb_clmulh(a1, b1);
	x2 = rvb_clmul(a1, b1);
	x1 = rvb_clmulh(a0, b0);
	x0 = rvb_clmul(a0, b0);
	t0 = a0 ^ a1;
	t2 = b0 ^ b1;
	t1 = rvb_clmulh(t0, t2);
	t0 = rvb_clmul(t0, t2);
	t1 = t1 ^ x1 ^ x3;
	t0 = t0 ^ x0 ^ x2;
	x2 = x2 ^ t1;
	x1 = x1 ^ t0;

	*ab1 = ((uint64_t) x2) | (((uint64_t) x3) << 32);
	*ab0 = ((uint64_t) x0) | (((uint64_t) x1) << 32);
}
*/

//  multiply z = ( z ^ rev(x) ) * h
//  non-karatsuba "compact" version

void rv32_ghash_mul(gf128_t * z, const gf128_t * x, const gf128_t * h)
{
	int i;
	uint32_t x0, x1, x2, x3, y;
	uint32_t z0, z1, z2, z3, z4;
	uint32_t t0, t1, t2;

	x0 = x->w[0];							//  new data
	x1 = x->w[1];
	x2 = x->w[2];
	x3 = x->w[3];

	z0 = z->w[0];							//  inline to avoid these loads
	z1 = z->w[1];
	z2 = z->w[2];
	z3 = z->w[3];

	x0 = rvb_grev(x0, 7);					//  reverse input x only
	x1 = rvb_grev(x1, 7);
	x2 = rvb_grev(x2, 7);
	x3 = rvb_grev(x3, 7);

	x0 = x0 ^ z0;							//  z is kept unreversed
	x1 = x1 ^ z1;
	x2 = x2 ^ z2;
	x3 = x3 ^ z3;

	y = h->w[3];							//  start from highest word
	z4 = rvb_clmulh(x3, y);
	z3 = rvb_clmul(x3, y);
	t1 = rvb_clmulh(x2, y);
	z2 = rvb_clmul(x2, y);
	z3 = z3 ^ t1;
	t1 = rvb_clmulh(x1, y);
	z1 = rvb_clmul(x1, y);
	z2 = z2 ^ t1;
	t1 = rvb_clmulh(x0, y);
	z0 = rvb_clmul(x0, y);
	z1 = z1 ^ t1;

#ifdef NO_SHIFTRED
	//  Mul reduction: 1 x CLMULH, 1 x CLMUL
	t1 = rvb_clmulh(z4, 0x87);
	t0 = rvb_clmul(z4, 0x87);
#else
	//  Shift reduction: 6 x SHIFT, 5 x XOR 
	t1 = (z4 >> 31) ^ (z4 >> 30) ^ (z4 >> 25);
	t0 = z4 ^ (z4 << 1) ^ (z4 << 2) ^ (z4 << 7);
#endif
	z1 = z1 ^ t1;
	z0 = z0 ^ t0;

	//  repeat 3 times

	for (i = 2; i >= 0; i--) {				//  towards less significant

		y = h->w[i];						//  unroll this if you like

		//  4 x CLMULH, 4 x CLMUL, 2 x XOR
		t1 = rvb_clmulh(x3, y);
		t0 = rvb_clmul(x3, y);
		z4 = z3 ^ t1;
		t1 = rvb_clmulh(x2, y);
		t2 = rvb_clmul(x2, y);
		z3 = z2 ^ t0 ^ t1;
		t1 = rvb_clmulh(x1, y);
		t0 = rvb_clmul(x1, y);
		z2 = z1 ^ t1 ^ t2;
		t1 = rvb_clmulh(x0, y);
		t2 = rvb_clmul(x0, y);
		z1 = z0 ^ t0 ^ t1;

#ifdef NO_SHIFTRED
		//  Mul reduction: 1 x CLMULH, 1 x CLMUL
		t1 = rvb_clmulh(z4, 0x87);
		t0 = rvb_clmul(z4, 0x87);
#else
		//  Shift reduction: 6 x SHIFT, 5 x XOR 
		t1 = (z4 >> 31) ^ (z4 >> 30) ^ (z4 >> 25);
		t0 = z4 ^ (z4 << 1) ^ (z4 << 2) ^ (z4 << 7);
#endif
		z1 = z1 ^ t1;						//  2 x XOR
		z0 = t2 ^ t0;

	}

	z->w[0] = z0;							//  inline to remove store
	z->w[1] = z1;
	z->w[2] = z2;
	z->w[3] = z3;
}
