//  test_main.c
//  2020-01-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Minimal unit tests for AES-128/192/256 (FIPS 197) and SM4 (GM/T 0002-2012).

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "aes_wrap.h"
#include "saes32.h"
#include "aes_saes32.h"
#include "aes_saes64.h"
#include "aes_otf_saes64.h"

#include "gcm_wrap.h"
#include "gcm_gfmul.h"


//  unit tests

int test_aes();								//  aes_test.c
int test_sm4();								//  sm4_test.c
int test_gcm();								//  gcm_test.c

//  generate "reference" hw testbench data for the instruction
//  output should match with hdl/saes32_tb.v

int test_hwtb()
{
	uint32_t rd, rs1, rs2, fn;

	rs1 = 0x00000000;
	rs2 = 0x00000000;

	for (fn = 0; fn < 24; fn++) {

		rd = saes32(rs1, rs2, fn);

		printf("[TB] rd=%08x rs1=%08x rs2=%08x fn=%02x\n", rd, rs1, rs2, fn);

		rs2 += 0x01234567;
	}

	return 0;
}

//  stub main: run unit tests

int main(int argc, char **argv)
{
	int fail = 0;

	//  generate hardware testbench data ?
	if (argc > 1 && strcmp(argv[1], "tb") == 0) {
		return test_hwtb();
	}
	//  algorithm tests

	printf("[INFO] === AES using SAES32 ===\n");

	aes128_enc_key = aes128_enc_key_saes32;	//  set encryption key
	aes192_enc_key = aes192_enc_key_saes32;
	aes256_enc_key = aes256_enc_key_saes32;

	aes128_enc_ecb = aes128_enc_ecb_saes32;	//  encrypt a block
	aes192_enc_ecb = aes192_enc_ecb_saes32;
	aes256_enc_ecb = aes256_enc_ecb_saes32;

	aes128_dec_key = aes128_dec_key_saes32;	//  set decryption key
	aes192_dec_key = aes192_dec_key_saes32;
	aes256_dec_key = aes256_dec_key_saes32;

	aes128_dec_ecb = aes128_dec_ecb_saes32;	//  decrypt a block
	aes192_dec_ecb = aes192_dec_ecb_saes32;
	aes256_dec_ecb = aes256_dec_ecb_saes32;

	fail += test_aes();						//  run tests with UUT = SAES32

	printf("[INFO] === AES using SAES64 / On-the-fly keying ===\n");

	aes128_enc_ecb = aes128_enc_otf_saes64;
	aes192_enc_ecb = aes192_enc_otf_saes64;
	aes256_enc_ecb = aes256_enc_otf_saes64;

	fail += test_aes();						//  run tests with UUT = OTF/64

	printf("[INFO] === AES using SAES64 ===\n");

	aes128_enc_key = aes128_enc_key_saes64;	//  set encryption key
	aes192_enc_key = aes192_enc_key_saes64;
	aes256_enc_key = aes256_enc_key_saes64;

	aes128_enc_ecb = aes128_enc_ecb_saes64;	//  encrypt a block
	aes192_enc_ecb = aes192_enc_ecb_saes64;
	aes256_enc_ecb = aes256_enc_ecb_saes64;

	aes128_dec_key = aes128_dec_key_saes64;	//  set decryption key
	aes192_dec_key = aes192_dec_key_saes64;
	aes256_dec_key = aes256_dec_key_saes64;

	aes128_dec_ecb = aes128_dec_ecb_saes64;	//  decrypt a block
	aes192_dec_ecb = aes192_dec_ecb_saes64;
	aes256_dec_ecb = aes256_dec_ecb_saes64;

	fail += test_aes();						//  run tests with UUT = SAES64



	printf("[INFO] === GCM using rv64_ghash_mul() ===\n");
	ghash_rev = rv64_ghash_rev;
	ghash_mul = rv64_ghash_mul;
	fail += test_gcm();

	printf("[INFO] === GCM using rv32_ghash_mul() ===\n");
	ghash_rev = rv32_ghash_rev;
	ghash_mul = rv32_ghash_mul;
	fail += test_gcm();

	printf("[INFO] === GCM using rv32_ghash_mul_kar() ===\n");
	ghash_rev = rv32_ghash_rev;
	ghash_mul = rv32_ghash_mul_kar;
	fail += test_gcm();

	printf("[INFO] === SM4 test ===\n");
	fail += test_sm4();

	if (fail == 0) {
		printf("[PASS] all tests passed.\n");
	} else {
		printf("[FAIL] %d test(s) failed.\n", fail);
	}

	return fail;
}
