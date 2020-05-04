//  sm4_test.c
//  2020-03-21  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Unit tests for SM4

#include "test_hex.h"
#include "sm4_wrap.h"

//  Test SM4

int test_sm4()
{
	uint8_t pt[16], ct[16], xt[16], key[16];
	uint32_t rk[SM4_RK_WORDS];
	int fail = 0;

	//  the sole test vector in the standard itself
	readhex(key, sizeof(key), "0123456789ABCDEFFEDCBA9876543210");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "0123456789ABCDEFFEDCBA9876543210");
	sm4_enc_ecb(ct, pt, rk);
	fail +=
		chkhex("SM4 Encrypt", ct, 16, "681EDF34D206965E86B3E94F536E4246");
	sm4_dec_key(rk, key);
	sm4_enc_ecb(xt, ct, rk);
	fail +=
		chkhex("SM4 Decrypt", xt, 16, "0123456789ABCDEFFEDCBA9876543210");

	//  from various sources..
	readhex(key, sizeof(key), "FEDCBA98765432100123456789ABCDEF");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "000102030405060708090A0B0C0D0E0F");
	sm4_enc_ecb(ct, pt, rk);
	fail +=
		chkhex("SM4 Encrypt", ct, 16, "F766678F13F01ADEAC1B3EA955ADB594");
	sm4_dec_key(rk, key);
	sm4_dec_ecb(xt, ct, rk);
	fail +=
		chkhex("SM4 Decrypt", xt, 16, "000102030405060708090A0B0C0D0E0F");

	readhex(key, sizeof(key), "EB23ADD6454757555747395B76661C9A");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "D294D879A1F02C7C5906D6C2D0C54D9F");
	sm4_enc_ecb(ct, pt, rk);
	fail +=
		chkhex("SM4 Encrypt", ct, 16, "865DE90D6B6E99273E2D44859D9C16DF");
	sm4_dec_key(rk, key);
	sm4_dec_ecb(xt, ct, rk);
	fail +=
		chkhex("SM4 Decrypt", xt, 16, "D294D879A1F02C7C5906D6C2D0C54D9F");

	readhex(key, sizeof(key), "F11235535318FA844A3CBE643169F59E");
	sm4_enc_key(rk, key);
	readhex(pt, sizeof(pt), "A27EE076E48E6F389710EC7B5E8A3BE5");
	sm4_enc_ecb(ct, pt, rk);
	fail +=
		chkhex("SM4 Encrypt", ct, 16, "94CFE3F59E8507FEC41DBE738CCD53E1");
	sm4_dec_key(rk, key);
	sm4_dec_ecb(xt, ct, rk);
	fail +=
		chkhex("SM4 Decrypt", xt, 16, "A27EE076E48E6F389710EC7B5E8A3BE5");

	return fail;
}
