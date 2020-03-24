//  endian.h
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Bit manipulation utilities.

#ifndef _ENDIAN_H_
#define _ENDIAN_H_

//  rotate left
#ifndef ROTL32
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#endif

//  load a 32-bit word (little-endian, non-aligned)
#ifndef GETU32_LE
#define GETU32_LE(v) \
	(((uint32_t) (v)[0])		^	(((uint32_t) (v)[1]) <<	 8) ^ \
	(((uint32_t) (v)[2]) << 16) ^	(((uint32_t) (v)[3]) << 24))
#endif

//  store a 32-bit word (little-endian, non-aligned)
#ifndef PUTU32_LE
#define PUTU32_LE(v, x) { \
	(v)[0] = (uint8_t)	(x);		(v)[1] = (uint8_t) ((x) >>	8); \
	(v)[2] = (uint8_t) ((x) >> 16); (v)[3] = (uint8_t) ((x) >> 24); }
#endif

#endif										/* _ENDIAN_H_ */
