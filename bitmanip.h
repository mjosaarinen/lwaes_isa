//  bitmanip.h
//  2020-03-07  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  bitmanip instruction emulation code

#ifndef _BITMANIP_H_
#define _BITMANIP_H_

#include <stdint.h>

//  === RV32 ===

//  generalized reverse GREV / GREVI
uint32_t rvb_grev(uint32_t rs1, uint32_t rs2);

//  generalized shuffle SHFL / SHFLI
uint32_t rvb_shfl(uint32_t rs1, uint32_t rs2);

//  generalized unshuffle UNSHFL / UNSHFLI
uint32_t rvb_unshfl(uint32_t rs1, uint32_t rs2);

//  === 32/64 ===

//  carryless multiply
uint32_t rvb_clmul(uint32_t rs1, uint32_t rs2);
uint32_t rvb_clmulh(uint32_t rs1, uint32_t rs2);
uint32_t rvb_clmulr(uint32_t rs1, uint32_t rs2);

//  rotate right ROR / RORI
uint32_t rvb_ror(uint32_t rs1, uint32_t rs2);

//  and with negate ANDN
uint64_t rvb_andn(uint64_t rs1, uint64_t rs2);

//  === RV64 ===

//  carryless multiply
uint64_t rvb_clmulw(uint64_t rs1, uint64_t rs2);
uint64_t rvb_clmulhw(uint64_t rs1, uint64_t rs2);
uint64_t rvb_clmulrw(uint64_t rs1, uint64_t rs2);

//  rotate right RORW / RORIW
uint64_t rvb_rorw(uint64_t rs1, uint64_t rs2);

//  generalized reverse GREVW / GREVIW
uint64_t rvb_grevw(uint64_t rs1, uint64_t rs2);

//  generalized shuffle SHFLW
uint64_t rvb_shflw(uint64_t rs1, uint64_t rs2);

//  generalized unshuffle UNSHFLW
uint64_t rvb_unshflw(uint64_t rs1, uint64_t rs2);

#endif
