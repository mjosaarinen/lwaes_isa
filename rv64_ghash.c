//  rv64_ghash.c
//  2020-03-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  64-bit GHASH bit-reverse and multiplication for GCM

#include "ghash.h"
#include "bitmanip.h"

//  disable shift reduction
//#define NO_SHIFTRED
//  disable karatsuba multiplication
//#define NO_KARATSUBA

//  reverse bits in bytes of a 128-bit block; do this for h and final value

void rv64_ghash_rev(gf128_t * z)
{
	z->d[0] = rvb_grevw(z->d[0], 7);
	z->d[1] = rvb_grevw(z->d[1], 7);
}

//  multiply z = ( z ^ rev(x) ) * h

void rv64_ghash_mul(gf128_t * z, const gf128_t * x, const gf128_t * h)
{
	uint64_t x0, x1, y0, y1;
	uint64_t z0, z1, z2, z3, t0, t1;

	x0 = x->d[0];							//  new input
	x1 = x->d[1];

	z0 = z->d[0];							//  inline to avoid these loads
	z1 = z->d[1];

	y0 = h->d[0];							//  h value already reversed
	y1 = h->d[1];

	//  2 x GREVW, 2 x XOR
	x0 = rvb_grevw(x0, 7);					//  reverse input x only
	x1 = rvb_grevw(x1, 7);
	x0 = x0 ^ z0;							//  z is updated
	x1 = x1 ^ z1;

	//  Top and bottom, witha and w/o Karatsuba: 2 x CLMULHW, 2 x CLMULW
	z3 = rvb_clmulhw(x1, y1);
	z2 = rvb_clmulw(x1, y1);
	z1 = rvb_clmulhw(x0, y0);
	z0 = rvb_clmulw(x0, y0);

#ifdef NO_SHIFTRED
	//  Mul reduction: 1 x CLMULHW, 1 x CLMULW, 1 x XOR
	t1 = rvb_clmulhw(z3, 0x87);
	t0 = rvb_clmulw(z3, 0x87);
	t1 = t1 ^ z2;
#else
	//  Shift reduction: 6 x SHIFT, 6 x XOR 
	t1 = (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57) ^ z2;
	t0 = z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
#endif

#ifdef NO_KARATSUBA
	//  Without Karatsuba; 2 x CLMULHW, 2 x CLMULW, 4 * XOR
	z3 = rvb_clmulhw(x0, y1);
	z2 = rvb_clmulw(x0, y1);
	z3 = z3 ^ t1;
	z2 = z2 ^ t0;
	t1 = rvb_clmulhw(x1, y0);
	t0 = rvb_clmulw(x1, y0);
	z3 = z3 ^ t1;
	z2 = z2 ^ t0;
#else
	//  With Karatsuba; 1 x CLMULHW, 1 x CLMULW, 8 * XOR
	z3 = z3 ^ t1 ^ z1;
	z2 = z2 ^ t0 ^ z0;
	x0 = x0 ^ x1;
	x1 = y0 ^ y1;
	t1 = rvb_clmulhw(x0, x1);
	t0 = rvb_clmulw(x0, x1);
	z3 = z3 ^ t1;
	z2 = z2 ^ t0;
#endif

#ifdef NO_SHIFTRED
	//  Mul reduction: 1 x CLMULHW, 1 x CLMULW, 1 x XOR
	t1 = rvb_clmulhw(z3, 0x87);
	t0 = rvb_clmulw(z3, 0x87);
	t1 = t1 ^ z2;
#else
	//  Shift reduction: 6 x SHIFT, 6 x XOR
	t1 = (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57) ^ z2;
	t0 = z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7);
#endif

	//  Low word; 2 x XOR
	x1 = z1 ^ t1;
	x0 = z0 ^ t0;

	z->d[0] = x0;							//  inline to avoid these stores
	z->d[1] = x1;
}
