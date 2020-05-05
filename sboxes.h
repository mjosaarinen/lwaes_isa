//  sboxes.h
//  2020-05-05  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Data for AES and SM4.

#ifndef _SBOXES_H_
#define _SBOXES_H_

#include <stdint.h>

//  AES Round Constants
extern const uint8_t aes_rcon[];

//  AES Forward S-Box
extern const uint8_t aes_sbox[256];

//  AES Inverse S-Box
extern const uint8_t aes_isbox[256];

//  SM4 Forward S-Box (there is no need for an inverse S-Box)
extern const uint8_t sm4_sbox[256];

#endif										//  _SBOXES_H_
