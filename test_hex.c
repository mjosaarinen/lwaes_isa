//  test_hex.c
//  2020-03-07  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  functions to facilitate simple runtime tests

#include "test_hex.h"

//  single hex digit

static int hexdigit(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	return -1;
}

//  read a hex string of "maxbytes", return byte length

size_t readhex(uint8_t * buf, size_t maxbytes, const char *str)
{
	size_t i;
	int h, l;

	for (i = 0; i < maxbytes; i++) {
		h = hexdigit(str[2 * i]);
		if (h < 0)
			return i;
		l = hexdigit(str[2 * i + 1]);
		if (l < 0)
			return i;
		buf[i] = (h << 4) + l;
	}

	return i;
}

//  print hexadecimal "data", length "len", with label "lab"

void prthex(const char *lab, const void *data, size_t len)
{
	size_t i;
	uint8_t x;

	printf("[TEST] %s ", lab);
	const char hex[] = "0123456789ABCDEF";

	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		putchar(hex[(x >> 4) & 0xF]);
		putchar(hex[x & 0xF]);
	}
	putchar('\n');
}

//  check "data" of "len" bytes against a hexadecimal test vector "ref"

int chkhex(const char *lab, const void *data, size_t len, const char *ref)
{
	size_t i;
	uint8_t x;
	int fail = 0;

	//  check equivalence
	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		if (hexdigit(ref[2 * i]) != ((x >> 4) & 0xF) ||
			hexdigit(ref[2 * i + 1]) != (x & 0x0F)) {
			fail = 1;
			break;
		}
	}

	if (i == len && hexdigit(ref[2 * len]) >= 0) {
		fail = 1;
	}

	printf("[%s] %s %s\n", fail ? "FAIL" : "PASS", lab, ref);

	if (fail) {
		prthex(lab, data, len);
	}

	return fail;
}
