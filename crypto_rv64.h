//  crypto_rv64.h
//  2020-05-02  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Prototypes for SAES64

#ifndef _CRYPTO_RV64_H_
#define _CRYPTO_RV64_H_

#include <stdint.h>

//  debug
#include <stdio.h>

//  main "hardware interface"
uint64_t saes64(uint64_t rs1, uint64_t rs2, int fn);

//  pseudo-ops
uint64_t saes64_encsm(uint64_t rs1, uint64_t rs2);
uint64_t saes64_encs(uint64_t rs1, uint64_t rs2);
uint64_t saes64_decsm(uint64_t rs1, uint64_t rs2);
uint64_t saes64_decs(uint64_t rs1, uint64_t rs2);

uint64_t saes64_imix(uint64_t rs1);

#endif
