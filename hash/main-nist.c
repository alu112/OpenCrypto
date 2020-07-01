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
#include "sha-common.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "sha3.h"


static void (*get_init(char *filename))(sha512_ctx_t *ctx)
{
	if (strstr(filename, "SHA1"))            return (void(*)(sha512_ctx_t*))sha1_init;
	else if (strstr(filename, "SHA224"))     return (void(*)(sha512_ctx_t*))sha224_init;
	else if (strstr(filename, "SHA256"))     return (void(*)(sha512_ctx_t*))sha256_init;
	else if (strstr(filename, "SHA512_224")) return sha512_224_init;
	else if (strstr(filename, "SHA512_256")) return sha512_256_init;
	else if (strstr(filename, "SHA384"))     return sha384_init;
	else if (strstr(filename, "SHA512"))     return sha512_init;
	else if (strstr(filename, "SHA3_224"))   return (void(*)(sha512_ctx_t*))sha3_224_init;
	else if (strstr(filename, "SHA3_256"))   return (void(*)(sha512_ctx_t*))sha3_256_init;
	else if (strstr(filename, "SHA3_384"))   return (void(*)(sha512_ctx_t*))sha3_384_init;
	else if (strstr(filename, "SHA3_512"))   return (void(*)(sha512_ctx_t*))sha3_512_init;
	else {
		printf("Can't find init function\n");
		return NULL;
	}
}

int sha_123(int argc, char *argv[])
{
	FILE *fp;
	char *filename;
	sha512_ctx_t ctx;
	void (*init)(sha512_ctx_t *ctx);
	int i, line;
	uint32_t msglen, mdlen, value;
	uint8_t md[64];
	uint8_t out[64];
	uint8_t msg[64*1024];
	uint8_t buf[64*2048];
	char filenames[][64] = {
		{"downloads/shabytetestvectors/SHA1ShortMsg.rsp"},
		{"downloads/shabytetestvectors/SHA1LongMsg.rsp"},
		{"downloads/shabytetestvectors/SHA224ShortMsg.rsp"},
		{"downloads/shabytetestvectors/SHA224LongMsg.rsp"},
		{"downloads/shabytetestvectors/SHA256ShortMsg.rsp"},
		{"downloads/shabytetestvectors/SHA256LongMsg.rsp"},
		{"downloads/shabytetestvectors/SHA512_224ShortMsg.rsp"},
		{"downloads/shabytetestvectors/SHA512_224LongMsg.rsp"},
		{"downloads/shabytetestvectors/SHA512_256ShortMsg.rsp"},
		{"downloads/shabytetestvectors/SHA512_256LongMsg.rsp"},
		{"downloads/shabytetestvectors/SHA384ShortMsg.rsp"},
		{"downloads/shabytetestvectors/SHA384LongMsg.rsp"},
		{"downloads/shabytetestvectors/SHA512ShortMsg.rsp"},
		{"downloads/shabytetestvectors/SHA512LongMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_224ShortMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_224LongMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_256ShortMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_256LongMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_384ShortMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_384LongMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_512ShortMsg.rsp"},
		{"downloads/sha-3bytetestvectors/SHA3_512LongMsg.rsp"}
	};

	for (i=0; i<ARRAY_SIZE(filenames); i++) {
		line = 0;
		filename = filenames[i];
		printf("process file: %s\n", filename);
		init = get_init(filename);
		fp = fopen(filename, "r");
		assert(fp);
		while (!feof(fp)) {
			value = 0;
			while (fgets(buf, sizeof(buf), fp)) {
				line++;
				strtok(buf, "\r\n");
				if (strstr(buf, "Len = ")) {value|=0x01;msglen=atoi(buf+6)/8;}
				else if (strstr(buf, "Msg = ")) {value|=0x02;hex2ba(buf+6, msg, sizeof(msg));}
				else if (strstr(buf, "MD = "))  {value|=0x04;hex2ba(buf+5, md, 64);}
				else if (strlen(buf) <= 2 && value == 0x07) break; /* \r\n */
				else if (strstr(buf, "[L = "))   {mdlen=atoi(buf+5);}
			}
			if (value != 7) break; /* end of file */
			/*
			 * NIST .rsp files are inconsistent of MD Length [L = xxx]
			 * they are bytes in SHA1 and SHA2 test files
			 * but are bits in SHA3 test files
			 */
			if (mdlen > 64) mdlen /= 8;

			assert(msglen <= sizeof(msg));

			init(&ctx);
			ctx.update(&ctx, msg, msglen);
			ctx.final(&ctx, out);
			if (memcmp(out, md, mdlen)) {
				fclose(fp);
				printf("failed at line %d of file %s\n", line, filename);
				exit(-1);
			}
		}
		fclose(fp);
	}

	printf("ALL SHA-1/2/3 TESTS PASSED!\n");
	return 0;
}

int sha_12_monte_carlo(int argc, char *argv[])
{
	FILE *fp;
	char *filename;
	sha512_ctx_t ctx;
	void (*init)(sha512_ctx_t *ctx);
	int i, j, k, line;
	uint32_t mdlen, value;
	uint8_t md0[64], md1[64], md2[64], md[64], out[64];
	uint8_t seed[64];
	uint8_t msg[64*3];
	char buf[256];
	char filenames[][64] = {
		"downloads/shabytetestvectors/SHA1Monte.rsp",
		"downloads/shabytetestvectors/SHA224Monte.rsp",
		"downloads/shabytetestvectors/SHA256Monte.rsp",
		"downloads/shabytetestvectors/SHA512_224Monte.rsp",
		"downloads/shabytetestvectors/SHA512_256Monte.rsp",
		"downloads/shabytetestvectors/SHA384Monte.rsp",
		"downloads/shabytetestvectors/SHA512Monte.rsp",
	};

	for (i=0; i<ARRAY_SIZE(filenames); i++) {
		line = 0;
		filename = filenames[i];
		printf("process file: %s\n", filename);
		init = get_init(filename);
		fp = fopen(filename, "r");
		assert(fp);

		value = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			line++;
			strtok(buf, "\r\n");
			if (strstr(buf, "[L = "))   {value|=1;mdlen=atoi(buf+5); if (mdlen>64) mdlen/=8;}
			else if (strstr(buf, "Seed = ")) {value|=2;hex2ba(buf+7, seed, sizeof(seed));}
			else if (strlen(buf) <= 2 && value == 0x03) break; /* \r\n */
		}

		for (j=0; j<100; j++) {
			value = 0;
			while (fgets(buf, sizeof(buf), fp)) {
				line++;
				strtok(buf, "\r\n");
				if (strstr(buf, "MD = "))  {value|=0x01;hex2ba(buf+5, md, 64);}
				else if (strlen(buf) <= 2 && value == 0x01) break; /* \r\n */
			}
			if (value != 1) break; /* end of file */

			memcpy(md0, seed, mdlen);
			memcpy(md1, seed, mdlen);
			memcpy(md2, seed, mdlen);
			init(&ctx);
			for (k=0; k<1000; k++) {
				memcpy(msg,         md0, mdlen);
				memcpy(msg+mdlen,   md1, mdlen);
				memcpy(msg+2*mdlen, md2, mdlen);
				ctx.update(&ctx, msg, 3*mdlen);
				ctx.final(&ctx, out);
				memcpy(md0, md1, mdlen);
				memcpy(md1, md2, mdlen);
				memcpy(md2, out, mdlen);
			}
			memcpy(seed, out, mdlen);
			if (memcmp(md, out, mdlen)) {
				fclose(fp);
				printf("failed at line %d of file %s\n", line, filename);
				exit(-1);
			}
		}
		fclose(fp);
	}

	printf("ALL SHA-1/2 Monte Carlo TESTS PASSED!\n");
	return 0;
}

int sha_3_monte_carlo(int argc, char *argv[])
{
	FILE *fp;
	char *filename;
	sha512_ctx_t ctx;
	void (*init)(sha512_ctx_t *ctx);
	int i, j, k, line;
	uint32_t mdlen, value;
	uint8_t md0[64], md[64], out[64];
	uint8_t seed[64];
	uint8_t msg[64*3];
	char buf[256];
	char filenames[][64] = {
		"downloads/sha-3bytetestvectors/SHA3_224Monte.rsp",
		"downloads/sha-3bytetestvectors/SHA3_256Monte.rsp",
		"downloads/sha-3bytetestvectors/SHA3_384Monte.rsp",
		"downloads/sha-3bytetestvectors/SHA3_512Monte.rsp",
	};

	for (i=0; i<ARRAY_SIZE(filenames); i++) {
		line = 0;
		filename = filenames[i];
		printf("process file: %s\n", filename);
		init = get_init(filename);
		fp = fopen(filename, "r");
		assert(fp);

		value = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			line++;
			strtok(buf, "\r\n");
			if (strstr(buf, "[L = "))   {value|=1;mdlen=atoi(buf+5); if (mdlen>64) mdlen/=8;}
			else if (strstr(buf, "Seed = ")) {value|=2;hex2ba(buf+7, seed, sizeof(seed));}
			else if (strlen(buf) <= 2 && value == 0x03) break; /* \r\n */
		}

		for (j=0; j<100; j++) {
			value = 0;
			while (fgets(buf, sizeof(buf), fp)) {
				line++;
				strtok(buf, "\r\n");
				if (strstr(buf, "MD = "))  {value|=0x01;hex2ba(buf+5, md, 64);}
				else if (strlen(buf) <= 2 && value == 0x01) break; /* \r\n */
			}
			if (value != 1) break; /* end of file */

			memcpy(md0, seed, mdlen);

			init(&ctx);
			for (k=0; k<1000; k++) {
				memcpy(msg, md0, mdlen);
				ctx.update(&ctx, msg, mdlen);
				ctx.final(&ctx, out);
				memcpy(md0, out, mdlen);
			}
			memcpy(seed, out, mdlen);
			if (memcmp(md, out, mdlen)) {
				fclose(fp);
				printf("failed at line %d of file %s\n", line, filename);
				exit(-1);
			}
		}
		fclose(fp);
	}

	printf("ALL SHA-3 Monte Carlo TESTS PASSED!\n");
	return 0;
}

int main(int argc, char *argv[])
{
	int result = 0;

	result = sha_123(argc, argv);
	if (!result)
		result = sha_12_monte_carlo(argc, argv);
	if (!result)
		result = sha_3_monte_carlo(argc, argv);

	return result;
}

