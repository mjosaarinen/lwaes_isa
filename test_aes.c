//  test_aes.c
//  2020-03-21  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Unit tests for AES-128/192/256

#include "test_hex.h"
#include "aes_enc.h"
#include "aes_dec.h"

//  Test AES

int test_aes()
{
	uint8_t pt[16], ct[16], xt[16], key[32];
	uint32_t rk[AES256_RK_WORDS];
	int fail = 0;

	//  FIPS 197 test vectors
	readhex(pt, sizeof(pt), "00112233445566778899AABBCCDDEEFF");
	readhex(key, sizeof(key),
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
	aes128_enc_key(rk, key);
	aes128_enc_ecb(ct, pt, rk);

	fail += chkhex("AES-128 Enc", ct, 16, "69C4E0D86A7B0430D8CDB78070B4C55A");
	aes128_dec_key(rk, key);
	aes128_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-128 Dec", xt, 16, "00112233445566778899AABBCCDDEEFF");

	aes192_enc_key(rk, key);
	aes192_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-192 Enc", ct, 16, "DDA97CA4864CDFE06EAF70A0EC0D7191");

	aes192_dec_key(rk, key);
	aes192_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-192 Dec", xt, 16, "00112233445566778899AABBCCDDEEFF");

	aes256_enc_key(rk, key);
	aes256_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-256 Enc", ct, 16, "8EA2B7CA516745BFEAFC49904B496089");

	aes256_dec_key(rk, key);
	aes256_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-256 Dec", xt, 16, "00112233445566778899AABBCCDDEEFF");

	//  another test vector set (picked from SP800-38A)
	readhex(key, sizeof(key), "2B7E151628AED2A6ABF7158809CF4F3C");
	aes128_enc_key(rk, key);
	readhex(pt, sizeof(pt), "6BC1BEE22E409F96E93D7E117393172A");
	aes128_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-128 Enc", ct, 16, "3AD77BB40D7A3660A89ECAF32466EF97");

	aes128_dec_key(rk, key);
	aes128_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-128 Dec", xt, 16, "6BC1BEE22E409F96E93D7E117393172A");

	readhex(key, sizeof(key),
			"8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B");
	aes192_enc_key(rk, key);
	readhex(pt, sizeof(pt), "AE2D8A571E03AC9C9EB76FAC45AF8E51");
	aes192_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-192 Enc", ct, 16, "974104846D0AD3AD7734ECB3ECEE4EEF");

	aes192_dec_key(rk, key);
	aes192_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-192 Dec", xt, 16, "AE2D8A571E03AC9C9EB76FAC45AF8E51");

	readhex(key, sizeof(key),
			"603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
	aes256_enc_key(rk, key);
	readhex(pt, sizeof(pt), "30C81C46A35CE411E5FBC1191A0A52EF");
	aes256_enc_ecb(ct, pt, rk);
	fail += chkhex("AES-256 Enc", ct, 16, "B6ED21B99CA6F4F9F153E7B1BEAFED1D");

	aes256_dec_key(rk, key);
	aes256_dec_ecb(xt, ct, rk);
	fail += chkhex("AES-256 Dec", xt, 16, "30C81C46A35CE411E5FBC1191A0A52EF");

	return fail;
}
