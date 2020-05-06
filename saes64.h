//  saes64.h
//  2020-05-02  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES64 -- replace with intrinsics.

#ifndef _SAES64_H_
#define _SAES64_H_

#include <stdint.h>

//  === (Pseudo) Instructions ===

//  SAES64.ENCSM:   Half of ShiftRows, SubBytes, and MixColumns
uint64_t saes64_encsm(uint64_t rs1, uint64_t rs2);

//  SAES64.ENCS:    Half of ShiftRows and SubBytes (last round)
uint64_t saes64_encs(uint64_t rs1, uint64_t rs2);

//  SAES64.DECSM:   Half of Inverse ShiftRows, SubBytes, and MixColumns
uint64_t saes64_decsm(uint64_t rs1, uint64_t rs2);

//  SAES64.DECS:    Half of Inverse ShiftRows and SubBytes (last round)
uint64_t saes64_decs(uint64_t rs1, uint64_t rs2);

//  SAES64.IMIX:    Inverse MixColumns for decryption key schedule
uint64_t saes64_imix(uint64_t rs1);

//  SAES.KS1:       Key Schedule 1 -- SubWord and opt. rotation, round const
uint64_t saes64_ks1(uint64_t rs1, uint8_t i);

//  SAES.KS1:       Key Schedule 1 -- SubWord and opt. rotation, round const
uint64_t saes64_ks2(uint64_t rs1, uint64_t rs2);

#endif										//  _SAES64_H_
