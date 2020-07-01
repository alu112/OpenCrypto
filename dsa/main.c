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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "bn.h"
#include "dsa.h"
#include "sha-common.h"
#include "sha1.h"

#ifdef DSA_TESTVECT
extern bn_t test_d;
extern bn_t test_k;
#else
bn_t test_d;
bn_t test_k;
#endif

int main(int argc, char *argv[])
{
	int line, value, i;
	FILE *fp;
	char filename[][128] = {
		"downloads/186-3dsatestvectors/SigGen.txt",
		"downloads/186-2dsatestvectors/SigGen.txt",
	};
	dsa_key_t key;
	dsa_sig_t signature;
	bn_t keycmp, r, s;

	uint8_t buf[1024];
	uint32_t plen;
	int mlen;
	uint8_t msg[256];
	bool passed;
	sha_ctx_t ctx;
	enum hash_id hash_id;
	uint8_t digest[SHA_DIGEST_LENGTH / 8];

	line = 0;
	memset(&buf, 0, sizeof(buf));
	for (i = 0; i < ARRAY_SIZE(filename); i++) {
		printf("process file: %s\n", filename[i]);
		fp = fopen(filename[i], "r");
		assert(fp);
		while (!feof(fp)) {
			value &= 1;
			while (fgets(buf, sizeof(buf), fp)) {
				line++;
				strtok(buf, "\r\n");
				if (strstr(buf, "[mod")) {
					buf[13] = 0;
					buf[20] = 0;
					buf[29] = 0;
					if (strstr(buf+7, "L=1024")) plen = 1024;
					else if(strstr(buf+7, "L=2048")) plen = 2048;
					else if (strstr(buf+7, "L=3072")) plen = 3072;
					key.dsa.keylen = plen;

					//if (strstr(buf+15, "N=160")) qlen = 160;
					//else if (strstr(buf+15, "N=224")) qlen = 224;
					//else if (strstr(buf+15, "N=256")) qlen = 256;

					if (strstr(buf+22, "SHA-224")) 		hash_id = eHASH_SHA224;
					else if (strstr(buf+22, "SHA-256"))	hash_id = eHASH_SHA256;
					else if (strstr(buf+22, "SHA-384"))	hash_id = eHASH_SHA384;
					else if (strstr(buf+22, "SHA-512"))	hash_id = eHASH_SHA512;
					else hash_id = eHASH_SHA1;

					hash_init(hash_id, &ctx);
				}
				if (strstr(buf, "P = ")) bn_hex2bn(buf+4, key.dsa.p);
				if(strstr(buf, "Q = "))  bn_hex2bn(buf+4, key.dsa.q);
				if(strstr(buf, "G = "))  bn_hex2bn(buf+4, key.dsa.g);

				if (strstr(buf, "Msg = "))    {value |= 0x02; mlen = hex2ba(buf + 6, msg, sizeof(msg));}
				else if (strstr(buf, "X = ")) {	value |= 0x04; bn_hex2bn(buf+4, test_d);}
				else if (strstr(buf, "Y = ")) {	value |= 0x08; bn_hex2bn(buf+4, keycmp);}
				else if (strstr(buf, "K = ")) {	value |= 0x10; bn_hex2bn(buf+4, test_k);}
				else if (strstr(buf, "R = ")) {	value |= 0x20; bn_hex2bn(buf + 4, r);}
				else if (strstr(buf, "S = ")) {	value |= 0x40; bn_hex2bn(buf + 4, s);}
				else if (strlen(buf) <= 2 && value == 0x7E) break; /* \r\n */
			}
			if (value != 0x7E) break; /* end of file */

			dsa_keygen(plen, &key);
			if (bn_cmp(key.pub, keycmp)) {
				printf("Keygen FAILED- Line: %d\n", line);
				return -1;
			}

			/* hash */
			ctx.init(&ctx);
			ctx.update(&ctx, msg, mlen);
			ctx.final(&ctx, digest);

			/*signature gen*/
			dsa_sign(&key, digest, ctx.md_len / 8, &signature);
			if (bn_cmp(signature.sig, s)) {
				printf("Signature - S - creation FAILED - Line: %d\n", line);
				return -1;
			}
			if (bn_cmp(signature.r, r)) {
				printf("Signature - R - creation FAILED - Line: %d\n", line);
				return -1;
			}

			/* verify signature*/
			passed = dsa_verify(&key, digest, ctx.md_len / 8, &signature);
			if (passed){
				bn_print("Signature - R = ", signature.r);
				bn_print("Signature - S = ", signature.sig);

				printf("Signature Verify PASSED\n");
			}
			else {
				printf("Signature Verify FAILED - Line: %d\n", line);
				return -1;
			}
			printf("\n");
		}
		fclose(fp);
	}
	printf("All test cases PASSED");
	return 0;
}

