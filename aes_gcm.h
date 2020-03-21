//  aes_gcm.h
//  2020-03-21  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Basic AES-GCM; 96-bit IV, no AAD, 128-bit auth tag padded at the end.
//  Ciphertext is always 16 bytes larger than plaintext.
//  Decrypt/verify routines (aesxxx_dec_vfy_gcm) return nonzero on failure.

#ifndef _AES_GCM_H_
#define _AES_GCM_H_

#include <stdint.h>
#include <stddef.h>

//  AES-GCM-128 Encrypt / Decrypt & Verify

void aes128_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12]);
int aes128_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12]);

//  AES-GCM-192 Encrypt / Decrypt & Verify

void aes192_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12]);
int aes192_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12]);

//  AES-GCM-256 Encrypt / Decrypt & Verify

void aes256_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12]);
int aes256_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12]);

#endif										/* _AES_GCM_H_ */
