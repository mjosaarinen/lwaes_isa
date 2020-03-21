//  bitmanip.h
//  2020-03-07  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  bitmanip instruction emulation code

#ifndef _BITMANIP_H_
#define _BITMANIP_H_

#include <stdint.h>

//  === RV32 ===

//  generalized reverse GREV / GREVI
uint32_t rv_grev(uint32_t rs1, uint32_t rs2);

//  generalized shuffle SHFL / SHFLI
uint32_t rv_shfl(uint32_t rs1, uint32_t rs2);

//  generalized unshuffle UNSHFL / UNSHFLI
uint32_t rv_unshfl(uint32_t rs1, uint32_t rs2);

//  === 32/64 ===

//  carryless multiply
uint32_t rv_clmul(uint32_t rs1, uint32_t rs2);
uint32_t rv_clmulh(uint32_t rs1, uint32_t rs2);
uint32_t rv_clmulr(uint32_t rs1, uint32_t rs2);

//  rotate right ROR / RORI
uint32_t rv_ror(uint32_t rs1, uint32_t rs2);

//  and with negate ANDN
uint64_t rv_andn(uint64_t rs1, uint64_t rs2);

//  === RV64 ===

//  carryless multiply
uint64_t rv_clmulw(uint64_t rs1, uint64_t rs2);
uint64_t rv_clmulhw(uint64_t rs1, uint64_t rs2);
uint64_t rv_clmulrw(uint64_t rs1, uint64_t rs2);

//  rotate right RORW / RORIW
uint64_t rv_rorw(uint64_t rs1, uint64_t rs2);

//  generalized reverse GREVW / GREVIW
uint64_t rv_grevw(uint64_t rs1, uint64_t rs2);

//  generalized shuffle SHFLW
uint64_t rv_shflw(uint64_t rs1, uint64_t rs2);

//  generalized unshuffle UNSHFLW
uint64_t rv_unshflw(uint64_t rs1, uint64_t rs2);

#endif
