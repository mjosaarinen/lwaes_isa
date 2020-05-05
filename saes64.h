//  saes64.h
//  2020-05-02  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES64 -- replace with intrinsics.

#ifndef _SAES64_H_
#define _SAES64_H_

#include <stdint.h>

//  "hardware simulation interface"

uint64_t saes64(uint64_t rs1, uint64_t rs2, int fn);

//  === (Pseudo) Instructions ===

//  AES Encryption
uint64_t saes64_encsm(uint64_t rs1, uint64_t rs2);
uint64_t saes64_encs(uint64_t rs1, uint64_t rs2);

//  AES Decryption

uint64_t saes64_decsm(uint64_t rs1, uint64_t rs2);
uint64_t saes64_decs(uint64_t rs1, uint64_t rs2);

//  AES Key Schedule

uint64_t saes64_imix(uint64_t rs1);
uint64_t saes64_ks1(uint64_t rs1, uint8_t i);
uint64_t saes64_ks2(uint64_t rs1, uint64_t rs2);

#endif										//  _SAES64_H_
