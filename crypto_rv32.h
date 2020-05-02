//  crypto_rv32.h
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES32

#ifndef _CRYPTO_RV32_H_
#define _CRYPTO_RV32_H_

#include <stdint.h>

//  Function codes -- see crypto_saes32.c
#define SAES32_ENCSM_FN		0
#define SAES32_ENCS_FN		1
#define SAES32_DECSM_FN		2
#define SAES32_DECS_FN		3
#define SSM4_ED_FN			4
#define SSM4_KS_FN			5

// #define AES_FN_RMC   (6 << 2)

//  SAES32: Instruction for a byte select, single S-box, and linear operation.

uint32_t saes32(uint32_t rs1, uint32_t rs2, int sn);

//  Pseudo-ops defined in the spec

#define SAES32_ENCSM(rs1, rs2, bs)	saes32(rs1, rs2, (SAES32_ENCSM_FN << 2) | bs)
#define SAES32_ENCS(rs1, rs2, bs)	saes32(rs1, rs2, (SAES32_ENCS_FN  << 2) | bs)
#define SAES32_DECSM(rs1, rs2, bs)	saes32(rs1, rs2, (SAES32_DECSM_FN << 2) | bs)
#define SAES32_DECS(rs1, rs2, bs)	saes32(rs1, rs2, (SAES32_DECS_FN  << 2) | bs)
#define SSM4_ED(rs1, rs2, bs)		saes32(rs1, rs2, (SSM4_ED_FN << 2) | bs)
#define SSM4_KS(rs1, rs2, bs)		saes32(rs1, rs2, (SSM4_KS_FN << 2) | bs)

#endif										//  _CRYPTO_RV32_H_
