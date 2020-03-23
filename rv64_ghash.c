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
	uint64_t a0, a1, b0, b1;
	uint64_t x0, x1, x2, x3, t0, t1;

	t0 = x->d[0];							//  new input
	t1 = x->d[1];

	a0 = z->d[0];							//  inline to avoid these loads
	a1 = z->d[1];

	b0 = h->d[0];							//  h value already reversed
	b1 = h->d[1];

	t0 = rvb_grevw(t0, 7);					//  reverse input x only
	t1 = rvb_grevw(t1, 7);
	a0 = a0 ^ t0;
	a1 = a1 ^ t1;

	//  Top and bottom words: 2 x CLMULHW, 2 x CLMULW
	x3 = rvb_clmulhw(a1, b1);
	x2 = rvb_clmulw(a1, b1);
	x1 = rvb_clmulhw(a0, b0);
	x0 = rvb_clmulw(a0, b0);

#ifdef NO_SHIFTRED
	//  Mul reduction: 1 x CLMULHW, 1 x CLMULW, 1 x XOR
	t1 = rvb_clmulhw(x3, 0x87);
	t0 = rvb_clmulw(x3, 0x87);
	t1 = t1 ^ x2;
#else
	//  Shift reduction: 6 x SHIFT, 6 x XOR 
	t1 = (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57) ^ x2;
	t0 = x3 ^ (x3 << 1) ^ (x3 << 2) ^ (x3 << 7);
#endif

#ifdef NO_KARATSUBA
	//  Without Karatsuba; 2 x CLMULHW, 2 x CLMULW, 4 * XOR
	x3 = rvb_clmulhw(a0, b1);
	x2 = rvb_clmulw(a0, b1);
	x3 = x3 ^ t1;
	x2 = x2 ^ t0;
	t1 = rvb_clmulhw(a1, b0);
	t0 = rvb_clmulw(a1, b0);
	x3 = x3 ^ t1;
	x2 = x2 ^ t0;
#else
	//  With Karatsuba; 1 x CLMULHW, 1 x CLMULW, 8 * XOR
	x3 = x3 ^ t1 ^ x1;
	x2 = x2 ^ t0 ^ x0;
	a0 = a0 ^ a1;
	a1 = b0 ^ b1;
	t1 = rvb_clmulhw(a0, a1);
	t0 = rvb_clmulw(a0, a1);
	x3 = x3 ^ t1;
	x2 = x2 ^ t0;
#endif

#ifdef NO_SHIFTRED
	//  Mul reduction: 1 x CLMULHW, 1 x CLMULW, 1 x XOR
	t1 = rvb_clmulhw(x3, 0x87);
	t0 = rvb_clmulw(x3, 0x87);
	t1 = t1 ^ x2;
#else
	//  Shift reduction: 6 x SHIFT, 8 x XOR
	t1 = (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57) ^ x2;
	t0 = x3 ^ (x3 << 1) ^ (x3 << 2) ^ (x3 << 7);
#endif

	//  Low word; 2 x XOR
	a1 = x1 ^ t1;
	a0 = x0 ^ t0;

	z->d[0] = a0;							//  inline to avoid these stores
	z->d[1] = a1;
}
