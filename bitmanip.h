//  bitmanip.h
//  2020-03-07  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  bitmanip instruction emulation code

#ifndef _BITMANIP_H_
#define _BITMANIP_H_

#include <stdint.h>

//  === RV32 ===

//  rotate right ROR / RORI
uint32_t rv_ror(uint32_t rs1, uint32_t rs2);

//  generalized reverse GREV / GREVI
uint32_t rv_grev(uint32_t rs1, uint32_t rs2);

//  generalized shuffle SHFL / SHFLI
uint32_t rv_shfl(uint32_t rs1, uint32_t rs2);

//  generalized unshuffle UNSHFL / UNSHFLI
uint32_t rv_unshfl(uint32_t rs1, uint32_t rs2);


//  === RV32/RV64 ===

//  and with negate ANDN
uint64_t rv_andn(uint64_t rs1, uint64_t rs2);


//  === RV64 ===

//  rotate right RORW / RORIW
uint64_t rv_rorw(uint64_t rs1, uint64_t rs2);

//  generalized reverse GREVW / GREVIW
uint64_t rv_grevw(uint64_t rs1, uint64_t rs2);

//  generalized shuffle SHFLW
uint64_t rv_shflw(uint64_t rs1, uint64_t rs2);

//  generalized unshuffle UNSHFLW
uint64_t rv_unshflw(uint64_t rs1, uint64_t rs2);

#endif
