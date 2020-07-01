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
#include "ec-gfp.h"
#include "ec-gf2m.h"
#include "ec-pem.h"

#include "sha-common.h"
#include "sha1.h"


int get_curvename(char *key_id, char *name)
{
	int rc = 0;


	name[0] = '\0';
	if (!strcmp(key_id, "P-192")) strcpy(name, "prime192v1");
	else if (!strcmp(key_id, "P-224")) strcpy(name, "secp224r1");
	else if (!strcmp(key_id, "P-256")) strcpy(name, "prime256v1");
	else if (!strcmp(key_id, "P-384")) strcpy(name, "secp384r1");
	else if (!strcmp(key_id, "P-521")) strcpy(name, "secp521r1");
	else if (!strcmp(key_id, "K-163")) strcpy(name, "sect163k1");
	else if (!strcmp(key_id, "K-233")) strcpy(name, "sect233k1");
	else if (!strcmp(key_id, "K-283")) strcpy(name, "sect283k1");
	else if (!strcmp(key_id, "K-409")) strcpy(name, "sect409k1");
	else if (!strcmp(key_id, "K-571")) strcpy(name, "sect571k1");
	else if (!strcmp(key_id, "B-163")) strcpy(name, "sect163r2");
	else if (!strcmp(key_id, "B-233")) strcpy(name, "sect233r1");
	else if (!strcmp(key_id, "B-283")) strcpy(name, "sect283r1");
	else if (!strcmp(key_id, "B-409")) strcpy(name, "sect409r1");
	else if (!strcmp(key_id, "B-571")) strcpy(name, "sect571r1");
	else rc = -1;

	if (strlen(name) == 0) rc = -1;
	printf("%s\n", name);
	return rc;
}

#ifdef EC_TESTVECT
extern bn_t ectest_k;
#else
bn_t ectest_k;
#endif

int main(int argc, char *argv[])
{
	FILE *fp;
	char filename[][128] = { "downloads/186-4ecdsatestvectors/SigGen.txt", "downloads/186-2ecdsatestvectors/SigGen.txt", };
	bool passed;
	int line, value, i, mlen;
	char name[64];
	ec_keyblob_t keya, keyb;
	gfp_point_t signcmp,sign;
	uint8_t buf[1024], msg[256], digest[SHA_DIGEST_LENGTH / 8];
	sha_ctx_t ctx;
	enum hash_id hash_id;
	void (*ecdsa_sign)(ec_keyblob_t*, uint8_t*, uint32_t, gfp_point_t*);
	bool (*ecdsa_verify)(ec_keyblob_t*, gfp_point_t*, uint8_t*, uint32_t,gfp_point_t*);
	int (*ecdsa_keygen)(char *, ec_keyblob_t * );

	line = 0;
	memset(&buf, 0, sizeof(buf));
	memset(&sign, 0, sizeof(sign));
	memset(&signcmp, 0, sizeof(signcmp));
	memset(&keya, 0, sizeof(keya));
	for (i = 0; i < ARRAY_SIZE(filename); i++) {
		printf("process file: %s\n", filename[i]);
		fp = fopen(filename[i], "r");
		assert(fp);
		while (!feof(fp)) {
			value &= 1;
			while (fgets(buf, sizeof(buf), fp)) {
				line++;
				strtok(buf, "\r\n");
				if (strchr(buf, '[')) {
					if (strstr(buf, "[P")) {
						printf("%s\n", buf);
						value = 0;//1;
						ecdsa_sign = ecdsa_sign_gfp;
						ecdsa_verify = ecdsa_verify_gfp;
						ecdsa_keygen = ec_keygen_gfp;
					} else if (strstr(buf, "[K") /* || strstr(buf, "[B")*/) {
						printf("%s\n", buf);
						value = 1;
						ecdsa_sign = ecdsa_sign_gf2m;
						ecdsa_verify = ecdsa_verify_gf2m;
						ecdsa_keygen = ec_keygen_gf2m;
					} else if (strstr(buf, "[B")) {
						printf("%s\n", buf);
						value = 1;
						ecdsa_sign = ecdsa_sign_gf2m;
						ecdsa_verify = ecdsa_verify_gf2m;
						ecdsa_keygen = ec_keygen_gf2m;
					} else
						value = 0;
					buf[6] = 0;
					get_curvename((buf + 1), name);
					ecdsa_keygen(name, &keya);
					buf[14] = 0;
					if (strstr(buf+7, "SHA-224"))      hash_id = eHASH_SHA224;
					else if (strstr(buf+7, "SHA-256")) hash_id = eHASH_SHA256;
					else if (strstr(buf+7, "SHA-384")) hash_id = eHASH_SHA384;
					else if (strstr(buf+7, "SHA-512")) hash_id = eHASH_SHA512;
					else                               hash_id = eHASH_SHA1;
					hash_init(hash_id, &ctx);
				}
				else if (strstr(buf, "Msg = ")) {     value |= 0x02; mlen = hex2ba(buf + 6, msg, sizeof(msg));}
				else if (strstr(buf, "d = ")) {  value |= 0x04; bn_hex2bn(buf + 4, keya.private);}
				else if (strstr(buf, "Qx = ")) { value |= 0x08; bn_hex2bn(buf + 5, keya.public.x);}
				else if (strstr(buf, "Qy = ")) { value |= 0x10; bn_hex2bn(buf + 5, keya.public.y);}
				else if (strstr(buf, "k = ")) {  value |= 0x20; bn_hex2bn(buf + 4, ectest_k);}
				else if (strstr(buf, "R = ")) {  value |= 0x40; bn_hex2bn(buf + 4, signcmp.x);}
				else if (strstr(buf, "S = ")) {  value |= 0x80; bn_hex2bn(buf + 4, signcmp.y);}
				else if (strlen(buf) <= 2 && value == 0xFF) break; /* \r\n */
			}
			if (value != 0xFF) break; /* end of file */

			keyb = keya;
			bn_clear(keyb.private);
			/* hash */
			ctx.init(&ctx);
			ctx.update(&ctx, msg, mlen);
			ctx.final(&ctx, digest);
			/*sign*/
			ecdsa_sign(&keya, digest, ctx.md_len / 8, &sign);

			if (!gfp_isequal(&sign, &signcmp)) {
				printf("incorrect signature, line number: %d\n", line);
				fclose(fp);
				return -1;
			}

			/*verify*/
			passed = ecdsa_verify(&keya, &keyb.public, digest, ctx.md_len / 8, &sign);
			if (passed)
				printf("test PASSED, line number: %d\n", line);
			else {
				printf("test FAILED, line number: %d\n", line);
				fclose(fp);
				return -1;
			}

		}
		fclose(fp);
	}
	return 0;
}
