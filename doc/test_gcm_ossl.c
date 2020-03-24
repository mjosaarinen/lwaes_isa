//  openssl_gcm.c
//  2020-03-24  Markku-Juhani O. Saarinen <mjos@pqshield.com>

//  test GCM against OpenSSL (to increase coverage)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include "aes_gcm.h"


static int gcm_encrypt(uint8_t * plaintext, int plaintext_len,
//              uint8_t * aad, int aad_len,
					   uint8_t * key,
					   uint8_t * iv, int iv_len, uint8_t * ciphertext,
					   uint8_t * tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		return 0;

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		return 0;

	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		return 0;

	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		return 0;

/*
	if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
		return 0;
*/
	if (1 !=
		EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return 0;
	ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		return 0;
	ciphertext_len += len;

	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		return 0;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static void hexvar(const uint8_t * v, size_t len, const char *lab)
{
	size_t i;

	printf("%s", lab);
	for (i = 0; i < len; i++)
		printf("%02X", v[i]);
	printf("\n");
}

static void rndvar(uint8_t * v, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		v[i] = random();

}

int test_gcm_ossl()
{
	int l, l1;
	uint8_t k[16], iv[12], p[1024], c1[1024], c2[1024];
	int fail = 0;

	srandom(time(NULL));

	for (l = 0; l < 1000; l++) {

		putchar('.');

		memset(c1, 0, l + 16);
		memset(c2, 0, l + 16);

		rndvar(k, 16);
		rndvar(iv, 12);
		rndvar(p, l);

		l1 = gcm_encrypt(p, l, k, iv, 12, c1, c1 + l);
		aes128_enc_gcm(c2, p, l, k, iv);

		if (l1 != l || memcmp(c1, c2, l + 16) != 0) {
			printf(" [FAIL] l=%d\n", l);
			hexvar(k, 16, "K\t");
			hexvar(iv, 12, "IV\t");
			hexvar(p, l, "P\t");
			hexvar(c1, l1 + 16, "C1\t");
			hexvar(c2, l + 16, "C2\t");
			fail++;
		}
	}
	printf("\n");

	return fail;
}
