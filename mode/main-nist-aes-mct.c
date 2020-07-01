/*
   Copyright 2020 Andrew Li, Gavin Li

   li.andrew.mail@gmail.com
   gavinux@gmail.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include "des.h"
#include "aes.h"
#include "sha-common.h"
#include "paddings.h"
#include "cipher-mode.h"

#include "files-nist-aes-mct.c"


static int get_vector(FILE *fp, uint32_t value, int *line, uint8_t *key, int *IVlen, uint8_t *iv, size_t *PTlen, uint8_t *pt, size_t *CTlen, uint8_t *ct)
{
	int fail = 1;
	uint8_t tmp[128];

	*IVlen = 0;
	while (fgets(tmp, sizeof(tmp), fp)) {
		(*line)++;
		strtok(tmp, "\r\n");
		if (strstr(tmp, "KEY = ")) {
			value|=0x01;
			hex2ba(tmp+6, key, 32);
		}
		else if (strstr(tmp, "IV = "))  {
			value|=0x02;
			*IVlen=(strlen(tmp+5)+1)/2;
			hex2ba(tmp+5, iv, 16);
		}
		else if (strstr(tmp, "PLAINTEXT = "))  {
			value|=0x04;
			*PTlen=(strlen(tmp+12)+1)/2;
			hex2ba(tmp+12, pt, 16);
		}
		else if (strstr(tmp, "CIPHERTEXT = ")) {
			value|=0x08;
			*CTlen=(strlen(tmp+13)+1)/2;
			hex2ba(tmp+13, ct, 16);
		}
		else if (strlen(tmp) <= 2 && value == 0x0F) {
			fail=0;
			break;
		} /* \r\n */
	}
	return fail;
}

static void (*get_init(char *filename))(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv)
{
	if (!strncmp(basename(filename), "CBC", 3))      return cbc_init;
	else if (!strncmp(basename(filename), "ECB", 3)) return ecb_init;
	else if (!strncmp(basename(filename), "CTR", 3)) return ctr_init;
	else if (!strncmp(basename(filename), "OFB", 3)) return ofb_init;
	else if (!strncmp(basename(filename), "CFB", 3)) return cfb_init;
	else {
		printf("Can't find init function\n");
		return NULL;
	}
}

static void newkey(int keylen, uint8_t *key, uint8_t *xt0, uint8_t *xt1)
{
	int k;
	switch(keylen) {
		case 128:
			for (k=0; k<16; k++) key[k] ^= xt1[k];
			break;
		case 192:
			for (k=0; k<8;  k++) key[k] ^= xt0[k+8];
			for (k=0; k<16; k++) key[k+8] ^= xt1[k];
			break;
		case 256:
			for (k=0; k<16; k++) key[k] ^= xt0[k];
			for (k=0; k<16; k++) key[k+16] ^= xt1[k];
			break;
	}

}

static int aes_mct_encrypt(FILE *fp, int Keylen, int *line, char *filename)
{
	aes_ctx_t  aes;
	cipher_ctx_t ctx;
	pad_ctx_t *pad_algo = NULL; /* &pad_pkcs5; &pad_x9p23; &pad_iso7816; &pad_zeros; */

	int     IVlen;
	size_t  n, PTlen, CTlen;
	int     fail_detected = 0;

	uint8_t key[32],  iv[16],  pt[16], ct[16], xt0[16], xt1[16], tmp[128];
	uint8_t key1[32], iv1[16], pt1[16];
	int i, j;
	uint32_t ecb_mode;
	void (*init)(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv);

	init = get_init(filename);
	assert(init != NULL);

	printf("[ENCRYPT]\n");

	ecb_mode = strncmp(basename(filename), "ECB", 3) ? 0 : 2;
	get_vector(fp, ecb_mode, line, key, &IVlen, iv, &PTlen, pt, &CTlen, ct);

	/* encrypt */
	printf("\nKeylen  = %d\n\n", Keylen);

	for (i=0; i<=99; i++) {
		ba2hex(key, Keylen/8, tmp); printf("Key[%2d] = %s\n", i, tmp);
		ba2hex(iv,  IVlen, tmp);    if (IVlen) printf(" IV[%2d] = %s\n", i, tmp);
		ba2hex(pt,  PTlen, tmp);    printf(" PT[%2d] = %s\n", i, tmp);

		aes_init(&aes, key, Keylen);
		init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
		/* j = 0 */
		n = ctx.encrypt(&ctx, pt, PTlen);
		memcpy(xt1, pt, n);
		if (!ecb_mode) memcpy(pt, iv, n);

		for (j=1; j<=999; j++) {
			n = ctx.encrypt(&ctx, pt, PTlen);
			memcpy(xt0, xt1, n);
			memcpy(xt1, pt, n);
			if (!ecb_mode) memcpy(pt, xt0, n);
		}
		ba2hex(xt1, PTlen, tmp); printf(" CT[%2d] = %s\n\n", i, tmp);
		if (memcmp(xt1, ct,  CTlen)) {fail_detected=1; printf("CT  doesn't match\n");}
		if (fail_detected) printf("encrypt failed at line %d of file %s\n", *line, filename);

		newkey(Keylen, key, xt0, xt1);
		if (!ecb_mode) {
			memcpy(iv, xt1, n);
			memcpy(pt, xt0, n);
		}

		if (i<99) {
			get_vector(fp, ecb_mode, line, key1, &IVlen, iv1, &PTlen, pt1, &CTlen, ct);

			if (memcmp(key, key1, Keylen/8)) {fail_detected=1; printf("Key doesn't match\n");}
			if (memcmp(iv,  iv1,  IVlen))    {fail_detected=1; printf("IV  doesn't match\n");}
			if (memcmp(pt,  pt1,  PTlen))    {fail_detected=1; printf("PT  doesn't match\n");}
		}
		assert(n == CTlen);
	}
	return fail_detected;
}

static int aes_mct_decrypt(FILE *fp, int Keylen, int *line, char *filename)
{
	aes_ctx_t  aes;
	cipher_ctx_t ctx;
	pad_ctx_t *pad_algo = NULL; /* &pad_pkcs5; &pad_x9p23; &pad_iso7816; &pad_zeros; */

	int     IVlen;
	size_t  n, PTlen, CTlen;
	int     fail_detected = 0;

	uint8_t key[32],  iv[16],  pt[16], ct[16], xt0[16], xt1[16], tmp[128];
	uint8_t key1[32], iv1[16], ct1[16];
	int i, j;
	uint32_t ecb_mode;
	void (*init)(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv);

	init = get_init(filename);
	assert(init != NULL);

	printf("[DECRYPT]\n");

	ecb_mode = strncmp(basename(filename), "ECB", 3) ? 0 : 2;
	get_vector(fp, ecb_mode, line, key, &IVlen, iv, &PTlen, pt, &CTlen, ct);

	/* decrypt */
	printf("\nKeylen  = %d\n\n", Keylen);

	for (i=0; i<=99; i++) {
		ba2hex(key, Keylen/8, tmp); printf("Key[%2d] = %s\n", i, tmp);
		ba2hex(iv,  IVlen, tmp);    printf(" IV[%2d] = %s\n", i, tmp);
		ba2hex(ct,  CTlen, tmp);    printf(" CT[%2d] = %s\n", i, tmp);

		aes_init(&aes, key, Keylen);
		init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
		n = ctx.decrypt(&ctx, ct, CTlen);
		memcpy(xt1, ct, n);
		if (!ecb_mode) memcpy(ct, iv, n);

		for (j=1; j<=999; j++) {
			memcpy(xt0, xt1, n);
			n = ctx.decrypt(&ctx, ct, CTlen);
			memcpy(xt1, ct, n);
			if (!ecb_mode) memcpy(ct, xt0, n);
		}
		ba2hex(xt1, PTlen, tmp); printf(" PT[%2d] = %s\n\n", i, tmp);
		if (memcmp(xt1, pt,  PTlen)) {fail_detected=1; printf("PT  doesn't match\n");}
		if (fail_detected)
			printf("decrypt failed at line %d of file %s\n", *line, filename);

		newkey(Keylen, key, xt0, xt1);
		if (!ecb_mode) {
			memcpy(iv, xt1, n);
			memcpy(ct, xt0, n);
		}

		if (i<99) {
			get_vector(fp, ecb_mode, line, key1, &IVlen, iv1, &PTlen, pt, &CTlen, ct1);

			if (memcmp(key, key1, Keylen/8)) {fail_detected=1; printf("Key doesn't match\n");}
			if (memcmp(iv,  iv1,  IVlen))    {fail_detected=1; printf("IV  doesn't match\n");}
			if (memcmp(ct,  ct1,  CTlen))    {fail_detected=1; printf("CT  doesn't match\n");}
		}

		assert(n == PTlen);
	}
	return fail_detected;
}

int main(int argc, char *argv[])
{
	int  i, line, Keylen, fail_detected;
	char *token;
	char *filename;
	FILE *fp;
	char tmp[128];

	for (i=0; i<ARRAY_SIZE(filenames) && !fail_detected; i++) {
		line = 0;
		fail_detected = 0;
		filename = filenames[i];
		printf("\nprocess file: %s\n", filename);

		fp = fopen(filename, "r");
		assert(fp != NULL);
		while (fgets(tmp, sizeof(tmp), fp)) {
			line++;
			strtok(tmp, "\r\n");
			if (token=strstr(tmp, "# Key Length : ")) Keylen = atoi(token + 15);
			else if (strstr(tmp, "[ENCRYPT]")) break;
		}

		fail_detected |= aes_mct_encrypt(fp, Keylen, &line, filename);

		while (fgets(tmp, sizeof(tmp), fp)) {
			line++;
			strtok(tmp, "\r\n");
			if (strstr(tmp, "[DECRYPT]")) break;
		}

		fail_detected |= aes_mct_decrypt(fp, Keylen, &line, filename);

		fclose(fp);
		if (fail_detected) exit(-1);
	}
	printf("ALL AES Monte Carlo TESTS PASSED!\n");
	return 0;
}

