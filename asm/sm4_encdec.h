//	sm4_encdec.h
//	2020-01-24	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Prototypes for SM4 (Chinese Encryption Standard) Encryption.

//	The decryption funtion is the same as encryption with the difference
//	of having a reversed key schedule. Hence we define both functions here.

#ifndef _SM4_ENCDEC_H_
#define _SM4_ENCDEC_H_

#include <stdint.h>

//	Size of the expanded key.
#define SM4_RK_WORDS  32

//	encrypt/decrypt a block, depending on ordering of rk
void sm4_encdec(uint8_t out[16], const uint8_t in[16],
				const uint32_t rk[SM4_RK_WORDS]);

//	expand a secret key for encryption
void sm4_enc_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16]);

//	expand a secret key for decryption
void sm4_dec_key(uint32_t rk[SM4_RK_WORDS], const uint8_t key[16]);

//	aliases
#define sm4_enc_ecb(ct, pt, rk) sm4_encdec(ct, pt, rk)
#define sm4_dec_ecb(pt, ct, rk) sm4_encdec(pt, ct, rk)

#endif										/* _SM4_ENCDEC_H_ */
