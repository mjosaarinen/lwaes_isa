//  test_main.c
//  2020-01-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Minimal unit tests for AES-128/192/256 (FIPS 197) and SM4 (GM/T 0002-2012).

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "enc1s.h"

//  unit tests

int test_aes();								//  test_aes.c
int test_gcm();								//  test_gcm.c
int test_sm4();								//  test_sm4.c

//  generate "reference" hw testbench data for the instruction
//  output should match with hdl/enc1s_tb.v

int test_hwtb()
{
	uint32_t rd, rs1, rs2, fn;

	rs1 = 0x00000000;
	rs2 = 0x00000000;

	for (fn = 0; fn < 24; fn++) {

		rd = enc1s(rs1, rs2, fn);

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
	fail += test_aes();
	fail += test_sm4();
	fail += test_gcm();

	if (fail == 0) {
		printf("[PASS] all tests passed.\n");
	} else {
		printf("[FAIL] %d test(s) failed.\n", fail);
	}

	return fail;
}
