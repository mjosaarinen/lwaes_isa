//  aes_otf_saes64.h
//  2020-05-06  Markku-Juhani O. Saarinen <mjos@pqhsield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  AES Encryption with on-the-fly key expansion.
//  *rk can point to expanded key or just the key.

#ifndef _AES_OTF_SAES64_H_
#define _AES_OTF_SAES64_H_

#include <stdint.h>

void aes128_enc_otf_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t * rk);

void aes192_enc_otf_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t * rk);

void aes256_enc_otf_saes64(uint8_t ct[16], const uint8_t pt[16],
						   const uint32_t * rk);

#endif
