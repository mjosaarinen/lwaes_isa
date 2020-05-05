//  saes32.h
//  2020-01-27  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES32 -- replace with intrinsics.

#ifndef _SAES32_H_
#define _SAES32_H_

#include <stdint.h>

//  Hardware simulation:
//  SAES32: Instruction for a byte select, single S-box, and linear operation.

uint32_t saes32(uint32_t rs1, uint32_t rs2, int sn);

//  === (Pseudo) Instructions ===

//  AES Encryption

uint32_t saes32_encsm(uint32_t rs1, uint32_t rs2, int bs);
uint32_t saes32_encs(uint32_t rs1, uint32_t rs2, int bs);

//  AES Decryption

uint32_t saes32_decsm(uint32_t rs1, uint32_t rs2, int bs);
uint32_t saes32_decs(uint32_t rs1, uint32_t rs2, int bs);

//  SM4 Encryption, Decryption and Key Schedule

uint32_t ssm4_ed(uint32_t rs1, uint32_t rs2, int bs);
uint32_t ssm4_ks(uint32_t rs1, uint32_t rs2, int bs);

#endif										//  _SAES32_H_
