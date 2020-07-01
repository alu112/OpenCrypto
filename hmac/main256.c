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

/*
 * echo -n "value" | openssl dgst -sha256 -hmac "key"
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac.h"

/*
 * test vectors from:
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA256.pdf
 */

int main(int argc, char *argv[])
{
	hmac_ctx_t hmac;
	int len, key_len;
	uint8_t key[64*2];
	uint8_t dgst[256/8];
	uint8_t expdgst[sizeof(dgst)];
	uint8_t keys1[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"};
	uint8_t data1[] = {"Sample message for keylen=blocklen"};
	uint8_t expected1[] = {"8BB9A1DB9806F20DF7F77B82138C7914D174D59E13DC4D0169C9057B133E1D62"};
	uint8_t keys2[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"};
	uint8_t data2[] = {"Sample message for keylen<blocklen"};
	uint8_t expected2[] = {"A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790"};
	uint8_t keys3[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263"};
	uint8_t data3[] = {"Sample message for keylen=blocklen"};
	uint8_t expected3[] = {"BDCCB6C72DDEADB500AE768386CB38CC41C63DBB0878DDB9C7A38A431B78378D"};
	uint8_t keys4[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"};
	uint8_t data4[] = {"Sample message for keylen<blocklen, with truncated tag"};
	uint8_t expected4[] = {"27A8B157839EFEAC98DF070B331D593618DDB985D403C0C786D23B5D132E57C7"};

	key_len = 64;
	hex2ba(keys1, key, key_len);
	hex2ba(expected1, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA256);
	hmac.update(&hmac, data1, strlen(data1));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys2)/2;
	hex2ba(keys2, key, key_len);
	hex2ba(expected2, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA256);
	hmac.update(&hmac, data2, strlen(data2));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys3)/2;
	hex2ba(keys3, key, key_len);
	hex2ba(expected3, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA256);
	hmac.update(&hmac, data3, strlen(data3));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys4)/2;
	hex2ba(keys4, key, key_len);
	hex2ba(expected4, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA256);
	hmac.update(&hmac, data4, strlen(data4));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));


	printf("ALL TEST PASSED!\n");
	return 0;
}


