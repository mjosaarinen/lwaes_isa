//  gcm_test.c
//  2020-03-21  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Unit tests for GCM AES-128/192/256 in simple mode. Selected from
//  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "test_hex.h"
#include "gcm_wrap.h"
#include "gcm_gfmul.h"

//  A GCM test

int test_gcm()
{
	uint8_t pt[100], ct[100], xt[100], k[32], iv[12];
	size_t mlen, clen;
	int flag, fail = 0;

	//  GCM AES-128, one-block message

	readhex(k, sizeof(k), "7FDDB57453C241D03EFBED3AC44E371C");
	readhex(iv, sizeof(iv), "EE283A3FC75575E33EFD4887");
	mlen = readhex(pt, sizeof(pt), "D5DE42B461646C255C87BD2962D3B9A2");
	clen = mlen + 16;
	memset(ct, 0, clen);
	aes128_enc_gcm(ct, pt, mlen, k, iv);
	fail += chkhex("GCM AES-128", ct, clen,
				   "2CCDA4A5415CB91E135C2A0F78C9B2FD"
				   "B36D1DF9B9D5E596F83E8B7F52971CB3");

	memset(xt, 0, mlen);
	flag = aes128_dec_vfy_gcm(xt, ct, clen, k, iv) ||
		memcmp(xt, pt, mlen) != 0;

	ct[rand() % clen] ^= 1 << (rand() & 7);	//  corrupt random bit

	flag |= !(aes128_dec_vfy_gcm(xt, ct, clen, k, iv) ||
			  memcmp(xt, pt, mlen) != 0);
	printf("[%s] GCM AES-128 verify / corrupt test\n",
		   flag ? "FAIL" : "PASS");
	if (flag)
		fail++;

	//  GCM AES-192, two-block message

	readhex(k, sizeof(k), "165C4AA5D78EE15F297D5D2EAE39EAAC"
			"3480FC50A6D9A98E");
	readhex(iv, sizeof(iv), "0E321E714C4A262350FC50FC");
	mlen = readhex(pt, sizeof(pt),
				   "5AFA41EFE94C0193FC9FE62FD6CFACC8"
				   "868725AB4965A5C9132D74179F0AEE72");
	clen = mlen + 16;
	memset(ct, 0, clen);
	aes192_enc_gcm(ct, pt, mlen, k, iv);
	fail += chkhex("GCM AES-192", ct, clen,
				   "5AB8AC904E7D4A627EE327B4629B6863"
				   "19936ABC709E8C0FB6817CB16D0C4F76"
				   "62BFEA782D6A05CD04030C433639B969");

	memset(xt, 0, mlen);
	flag = aes192_dec_vfy_gcm(xt, ct, clen, k, iv) ||
		memcmp(xt, pt, mlen) != 0;

	ct[rand() % clen] ^= 1 << (rand() & 7);	//  corrupt random bit

	flag |= !(aes192_dec_vfy_gcm(xt, ct, clen, k, iv) ||
			  memcmp(xt, pt, mlen) != 0);
	printf("[%s] GCM AES-192 verify / corrupt test\n",
		   flag ? "FAIL" : "PASS");
	if (flag)
		fail++;

	//  GCM AES-256, 51-byte message

	readhex(k, sizeof(k), "1FDED32D5999DE4A76E0F8082108823A"
			"EF60417E1896CF4218A2FA90F632EC8A");
	readhex(iv, sizeof(iv), "1F3AFA4711E9474F32E70462");
	mlen = readhex(pt, sizeof(pt),
				   "06B2C75853DF9AEB17BEFD33CEA81C63"
				   "0B0FC53667FF45199C629C8E15DCE41E"
				   "530AA792F796B8138EEAB2E86C7B7BEE" "1D40B0");
	clen = mlen + 16;
	memset(ct, 0, clen);
	aes256_enc_gcm(ct, pt, mlen, k, iv);
	fail += chkhex("GCM AES-256", ct, clen,
				   "91FBD061DDC5A7FCC9513FCDFDC9C3A7"
				   "C5D4D64CEDF6A9C24AB8A77C36EEFBF1"
				   "C5DC00BC50121B96456C8CD8B6FF1F8B"
				   "3E480F" "30096D340F3D5C42D82A6F475DEF23EB");
	memset(xt, 0, mlen);
	flag = aes256_dec_vfy_gcm(xt, ct, clen, k, iv) ||
		memcmp(xt, pt, mlen) != 0;

	ct[rand() % clen] ^= 1 << (rand() & 7);	//  corrupt random bit

	flag |= !(aes256_dec_vfy_gcm(xt, ct, clen, k, iv) ||
			  memcmp(xt, pt, mlen) != 0);
	printf("[%s] GCM AES-256 verify / corrupt test\n",
		   flag ? "FAIL" : "PASS");
	if (flag)
		fail++;

	return fail;
}
