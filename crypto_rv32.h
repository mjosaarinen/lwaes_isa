//  crypto_rv32.h
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES32 and ENC4S.

#ifndef _CRYPTO_RV32_H_
#define _CRYPTO_RV32_H_

#include <stdint.h>

//  Function codes -- see crypto_saes32.c

#define AES_FN_ENC	(0 << 2)
#define AES_FN_FWD	(1 << 2)
#define AES_FN_DEC	(2 << 2)
#define AES_FN_REV	(3 << 2)
#define SM4_FN_ENC	(4 << 2)
#define SM4_FN_KEY	(5 << 2)

// #define AES_FN_RMC   (6 << 2)

//  SAES32: Instruction for a byte select, single S-box, and linear operation.

uint32_t saes32(uint32_t rs1, uint32_t rs2, int sn);

//  Pseudo-ops defined in the spec

#define SAES32_ENCS(rs1, rs2, bs)	saes32(rs1, rs2, AES_FN_ENC | bs)
#define SAES32_ENCSM(rs1, rs2, bs)	saes32(rs1, rs2, AES_FN_FWD | bs)
#define SAES32_DECS(rs1, rs2, bs)	saes32(rs1, rs2, AES_FN_DEC | bs)
#define SAES32_DECSM(rs1, rs2, bs)	saes32(rs1, rs2, AES_FN_REV | bs)

#define SSM4_ED(rs1, rs2, bs)		saes32(rs1, rs2, SM4_FN_ENC | bs)
#define SSM4_KS(rs1, rs2, bs)		saes32(rs1, rs2, SM4_FN_KEY | bs)

#endif										//  _CRYPTO_RV32_H_
