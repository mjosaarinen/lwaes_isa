//  bitmanip.h
//  2020-03-07  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  bitmanip instruction emulation code

#ifndef _BITMANIP_H_
#define _BITMANIP_H_

#include <stdint.h>

//  generalized reverse GREV / GREVI
uint32_t rv32b_grev(uint32_t rs1, uint32_t rs2);

//  generalized shuffle SHFL / SHFLI
uint32_t rv32b_shfl(uint32_t rs1, uint32_t rs2);

//  generalized unshuffle UNSHFL / UNSHFLI
uint32_t rv32b_unshfl(uint32_t rs1, uint32_t rs2);

//  carryless multiply
uint32_t rv32b_clmul(uint32_t rs1, uint32_t rs2);
uint32_t rv32b_clmulh(uint32_t rs1, uint32_t rs2);
uint32_t rv32b_clmulr(uint32_t rs1, uint32_t rs2);

//  rotate right ROR / RORI
uint32_t rv32b_ror(uint32_t rs1, uint32_t rs2);

//  and with negate ANDN
uint64_t rv32b_andn(uint32_t rs1, uint32_t rs2);
uint64_t rv64b_andn(uint64_t rs1, uint64_t rs2);

//  carryless multiply
uint64_t rv64b_clmul(uint64_t rs1, uint64_t rs2);
uint64_t rv64b_clmulh(uint64_t rs1, uint64_t rs2);
uint64_t rv64b_clmulr(uint64_t rs1, uint64_t rs2);

//  rotate right ROR / RORI
uint64_t rv64b_ror(uint64_t rs1, uint64_t rs2);

//  generalized reverse GREVW / GREVIW
uint64_t rv64b_grev(uint64_t rs1, uint64_t rs2);

//  generalized shuffle SHFL
uint64_t rv64b_shfl(uint64_t rs1, uint64_t rs2);

//  generalized unshuffle UNSHFL
uint64_t rv64b_unshfl(uint64_t rs1, uint64_t rs2);

#endif										//  _BITMANIP_H_
