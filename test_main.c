//  test_main.c
//  2020-01-23  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  Minimal unit tests for AES-128/192/256 (FIPS 197) and SM4 (GM/T 0002-2012).

#include "test_hex.h"

//  prototypes for high level primitives

#include "aes_enc.h"
#include "aes_dec.h"
#include "sm4_encdec.h"

//  the instruction

#include "enc1s.h"

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
    fail += chkhex("SM4 Encrypt", ct, 16, "681EDF34D206965E86B3E94F536E4246");
    sm4_dec_key(rk, key);
    sm4_enc_ecb(xt, ct, rk);
    fail += chkhex("SM4 Decrypt", xt, 16, "0123456789ABCDEFFEDCBA9876543210");

    //  from various sources..
    readhex(key, sizeof(key), "FEDCBA98765432100123456789ABCDEF");
    sm4_enc_key(rk, key);
    readhex(pt, sizeof(pt), "000102030405060708090A0B0C0D0E0F");
    sm4_enc_ecb(ct, pt, rk);
    fail += chkhex("SM4 Encrypt", ct, 16, "F766678F13F01ADEAC1B3EA955ADB594");
    sm4_dec_key(rk, key);
    sm4_dec_ecb(xt, ct, rk);
    fail += chkhex("SM4 Decrypt", xt, 16, "000102030405060708090A0B0C0D0E0F");

    readhex(key, sizeof(key), "EB23ADD6454757555747395B76661C9A");
    sm4_enc_key(rk, key);
    readhex(pt, sizeof(pt),  "D294D879A1F02C7C5906D6C2D0C54D9F");
    sm4_enc_ecb(ct, pt, rk);
    fail += chkhex("SM4 Encrypt", ct, 16, "865DE90D6B6E99273E2D44859D9C16DF");
    sm4_dec_key(rk, key);
    sm4_dec_ecb(xt, ct, rk);
    fail += chkhex("SM4 Decrypt", xt, 16, "D294D879A1F02C7C5906D6C2D0C54D9F");

    readhex(key, sizeof(key), "F11235535318FA844A3CBE643169F59E");
    sm4_enc_key(rk, key);
    readhex(pt, sizeof(pt), "A27EE076E48E6F389710EC7B5E8A3BE5");
    sm4_enc_ecb(ct, pt, rk);
    fail += chkhex("SM4 Encrypt", ct, 16, "94CFE3F59E8507FEC41DBE738CCD53E1");
    sm4_dec_key(rk, key);
    sm4_dec_ecb(xt, ct, rk);
    fail += chkhex("SM4 Decrypt", xt, 16, "A27EE076E48E6F389710EC7B5E8A3BE5");

    return fail;
}

//  generate "reference" hw testbench data for the instruction
//  output should match with hdl/enc1s_tb.v

int test_hwtb()
{
    uint32_t rd, rs1, rs2, fn;

    rs1 = 0x00000000;
    rs2 = 0x00000000;

    for (fn = 0; fn < 24; fn++) {

        rd = enc1s(rs1, rs2, fn);

        printf("[TB] rd=%08x rs1=%08x rs2=%08x fn=%02x\n",
            rd, rs1, rs2, fn);

        rs2 += 0x01234567;
    }

    return 0;
}

//  stub main: run unit tests

int main(int argc, char **argv)
{
    int fail = 0;

    //  generate hardware testbench data
    if (argc > 1 && strcmp(argv[1], "tb") == 0) {
        return test_hwtb();
    }

    //  full algorithm tests

    fail += test_aes();
    fail += test_sm4();

    if (fail == 0) {
        printf("[PASS] all tests passed.\n");
    } else {
        printf("[FAIL] %d test(s) failed.\n", fail);
    }

    return fail;
}

