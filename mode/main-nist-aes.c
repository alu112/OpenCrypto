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

#include "files-nist-aes.c"

int main(int argc, char *argv[])
{
	size_t n;
	//tdes_ctx_t tdes;
	aes_ctx_t  aes;
	cipher_ctx_t ctx;
	pad_ctx_t *pad_algo = NULL; /* &pad_pkcs5; &pad_x9p23; &pad_iso7816; &pad_zeros; */

	int     Keylen = 256;
	size_t  PTlen, CTlen;
	int     status  = 0;
	int     fail_detected = 0;

	uint8_t key[256], iv[256], pt[512], ct[512], buf[512];
	uint8_t Key[1024], IV[1024], PT[1024], CT[1024];
	uint32_t value;

	char *token;
	char *filename;
	int i, line;
	FILE *fp;
	void (*init)(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv);

	for (i=0; i<ARRAY_SIZE(filenames); i++) {
		line = 0;
		filename = filenames[i];
		printf("process file: %s\n", filename);
		if (!strncmp(basename(filename), "CBC", 3))
			init = cbc_init;
		else if (!strncmp(basename(filename), "ECB", 3))
			init = ecb_init;
		else if (!strncmp(basename(filename), "CTR", 3))
			init = ctr_init;
		else if (!strncmp(basename(filename), "OFB", 3))
			init = ofb_init;
		else if (!strncmp(basename(filename), "CFB", 3))
			init = cfb_init;
		else {
			printf("Can't find init function\n");
			exit(-1);
		}
		fp = fopen(filename, "r");
		while (!feof(fp)) {
			status = 0;
			value  = 0;
			if (!strncmp(basename(filename), "ECB", 3))
				value |= 0x02;
			while (fgets(buf, sizeof(buf), fp)) {
				line++;
				strtok(buf, "\r\n");
				if (token=strstr(buf, "# Key Length : ")) Keylen = atoi(token + 15);
				else if (strstr(buf, "KEY = ")) {value|=0x01;strncpy(Key, buf+6, Keylen/4); Key[Keylen/4]=0;}
				else if (strstr(buf, "IV = "))  {value|=0x02;strncpy(IV,  buf+5, Keylen/4);  IV[128/4]=0;}
				else if (strstr(buf, "PLAINTEXT = "))  {value|=0x04;strcpy(PT,  buf+12);}
				else if (strstr(buf, "CIPHERTEXT = ")) {value|=0x08;strcpy(CT, buf+13);}
				else if (!strncmp(buf, "FAIL", 4)) status = 1;
				else if (strlen(buf) <= 2 && value == 0x0F) break; /* \r\n */
			}

			PTlen = (strlen(PT)+1)/2;
			CTlen = (strlen(CT)+1)/2;
			hex2ba(Key, key, sizeof(key));
			hex2ba(IV,  iv,  sizeof(iv));
			hex2ba(PT,  pt,  sizeof(pt));
			hex2ba(CT,  ct,  sizeof(ct));

			aes_init(&aes, key, Keylen);

			/* encrypt */
			memcpy(buf, pt, PTlen);
			init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
			n = ctx.encrypt(&ctx, buf, PTlen);
			assert(n == CTlen);
			if (memcmp(ct, buf, CTlen)) {
				printf("encrypt failed at line %d of file %s\n", line, filename);
				fail_detected = 1;
			}
			else
				printf("encrypt succeeded at line %d of file %s\n", line, filename);

			/* decrypt */
			memcpy(buf, ct, CTlen);
			init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
			n = ctx.decrypt(&ctx, buf, CTlen);
			assert(n == PTlen);
			if (memcmp(pt, buf, PTlen)) {
				printf("decrypt failed at line %d of file %s\n", line, filename);
				fail_detected = 1;
			}
			else
				printf("decrypt succeeded at line %d of file %s\n", line, filename);


			if (fail_detected) {
				if (status)
					printf("The test at line %d of file %s should FAIL\n", line, filename);
				else {
					printf("Fail detected at line %d of file %s, Quit Test!\n", line, filename);
					break;
				}
			}

		}
		fclose(fp);

		if (fail_detected && !status) exit(-1);
	}
	printf("ALL AES TESTS PASSED!\n");
	return 0;
}

