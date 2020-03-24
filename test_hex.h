//  test_hex.h
//  2020-03-07  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  functions to facilitate simple runtime tests

#ifndef _TEST_HEX_H_
#define _TEST_HEX_H_

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

//  read a hex string of "maxbytes", return byte length
size_t readhex(uint8_t * buf, size_t maxbytes, const char *str);

//  print hexadecimal "data", length "len", with label "lab"
void prthex(const char *lab, const void *data, size_t len);

//  check "data" of "len" bytes against a hexadecimal test vector "ref"
int chkhex(const char *lab, const void *data, size_t len, const char *ref);

#endif
