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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha-common.h"
#include "aes.h"
#include "gmac.h"

/*
 * test vectors coming from 
 * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
 */
int main(int argc, char *argv[])
{
	aes_ctx_t    aes;
	gmac_ctx_t   ctx;
	int     ok;
	uint8_t key[256], iv[256], aad[256], tag[32], newtag[32], pt[512], ct[512], buf[512];

	int     Keylen = 256;
	size_t  IVlen  = 96;
	size_t  PTlen  = 128;
	int     AADlen = 128;
	int     Taglen = 128;
	int     status  = 0;
	int     fail_detected = 0;
	uint8_t Key[512];
	uint8_t IV[512];
	uint8_t PT[512];
	uint8_t AAD[512];
	uint8_t CT[512];
	uint8_t Tag[128];
	uint32_t value;

	char *token;
	char *filename;
	char filenames[][64] = {
		{"downloads/gcmtestvectors/gcmEncryptExtIV256.rsp"},
		{"downloads/gcmtestvectors/gcmEncryptExtIV192.rsp"},
		{"downloads/gcmtestvectors/gcmEncryptExtIV128.rsp"},
		{"downloads/gcmtestvectors/gcmDecrypt256.rsp"},
		{"downloads/gcmtestvectors/gcmDecrypt192.rsp"},
		{"downloads/gcmtestvectors/gcmDecrypt128.rsp"},
	};
	int i, line;
	FILE *fp;

	for (i=0; i<ARRAY_SIZE(filenames); i++) {
		line = 0;
		filename = filenames[i];
		fp = fopen(filename, "r");
		while (!feof(fp)) {
			status = 0;
			value  = 0;
			while (fgets(buf, sizeof(buf), fp)) {
				line++;
				if (token=strstr(buf, "[Keylen = ")) Keylen = atoi(token + 10);
				else if (token=strstr(buf, "[IVlen = "))  IVlen  = atoi(token + 9);
				else if (token=strstr(buf, "[PTlen = "))  PTlen  = atoi(token + 9);
				else if (token=strstr(buf, "[AADlen = ")) AADlen = atoi(token + 10);
				else if (token=strstr(buf, "[Taglen = ")) Taglen = atoi(token + 10);
				else if (strstr(buf, "Key = ")) {value|=0x01;strncpy(Key, buf+6, Keylen/4); Key[Keylen/4]=0;}
				else if (strstr(buf, "IV = "))  {value|=0x02;strncpy(IV,  buf+5, IVlen/4);  IV[IVlen/4]=0;}
				else if (strstr(buf, "PT = "))  {value|=0x04;strncpy(PT,  buf+5, PTlen/4);  PT[PTlen/4]=0;}
				else if (strstr(buf, "AAD = ")) {value|=0x08;strncpy(AAD, buf+6, AADlen/4); AAD[AADlen/4]=0;}
				else if (strstr(buf, "CT = "))  {value|=0x10;strncpy(CT,  buf+5, PTlen/4);  CT[PTlen/4]=0;}
				else if (strstr(buf, "Tag = ")) {value|=0x20;strncpy(Tag, buf+6, Taglen/4); Tag[Taglen/4]=0;}
				else if (!strncmp(buf, "FAIL", 4)) status = 1;
				else if (strlen(buf) <= 4 && value == 0x3F) break; /* \r\n */
			}

			hex2ba(Key, key, sizeof(key));
			hex2ba(IV,  iv,  sizeof(iv));
			hex2ba(PT,  pt,  sizeof(pt));
			hex2ba(AAD, aad, sizeof(aad));
			hex2ba(CT,  ct,  sizeof(ct));
			hex2ba(Tag, tag, sizeof(tag));

			aes_init(&aes, key, Keylen);

			/* encrypt */
			memcpy(buf, pt, PTlen/8);
			gmac_init(&ctx, iv, IVlen/8, aad, AADlen/8, Taglen/8, (blk_ctx_t *)&aes);
			ctx.encrypt(&ctx, buf, PTlen/8, newtag);
			if (memcmp(ct, buf, PTlen/8)) {
				printf("encrypt failed at line %d of file %s\n", line, filename);
				fail_detected = 1;
			}
			else
				printf("encrypt succeeded\n");
			if (memcmp(tag, newtag, Taglen/8)) {
				printf("tag verify failed at line %d of file %s\n", line, filename);
				fail_detected = 1;
			}
			else
				printf("tag verify succeeded\n");

			/* decrypt */
			memcpy(buf, ct, PTlen/8);
			gmac_init(&ctx, iv, IVlen/8, aad, AADlen/8, Taglen/8, (blk_ctx_t *)&aes);
			ok = ctx.decrypt(&ctx, buf, PTlen/8, tag);

			if (memcmp(pt, buf, PTlen/8)) {
				printf("decrypt failed at line %d of file %s\n", line, filename);
				fail_detected = 1;
			}
			else
				printf("decrypt succeeded\n");
			if (ok != 0) {
				printf("tag verify failed at line %d of file %s\n", line, filename);
				fail_detected = 1;
			}
			else
				printf("tag verify succeeded\n");

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
	printf("ALL GCM/GMAC TESTS PASSED!\n");
	return 0;
}

