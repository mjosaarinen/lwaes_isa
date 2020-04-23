//  aes_wrap.c
//  2020-04-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  AES 128/192/256 block encryption and decryption

#include "aes_wrap.h"

//  externally visible pointers

void (*aes_enc_rounds)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[], int nr) = aes_rv32_enc;
void (*aes_dec_rounds)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[], int nr) = aes_rv32_dec;
