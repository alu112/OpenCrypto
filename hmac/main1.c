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
 * echo -n "value" | openssl dgst -sha1 -hmac "key"
 * 57443a4c052350a44638835d64fd66822f813319
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac.h"

/*
 * test vectors from:
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA1.pdf
 */

int main(int argc, char *argv[])
{
	hmac_ctx_t hmac;
	int len, key_len;
	uint8_t key[64*2];
	uint8_t dgst[160/8];
	uint8_t expdgst[sizeof(dgst)];
	uint8_t keys1[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"};
	uint8_t data1[] = {"Sample message for keylen=blocklen"};
	uint8_t expected1[] = {"5FD596EE78D5553C8FF4E72D266DFD192366DA29"};
	uint8_t keys2[] = {"000102030405060708090A0B0C0D0E0F10111213"};
	uint8_t data2[] = {"Sample message for keylen<blocklen"};
	uint8_t expected2[] = {"4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807"};
	uint8_t keys3[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263"};
	uint8_t data3[] = {"Sample message for keylen=blocklen"};
	uint8_t expected3[] = {"2D51B2F7750E410584662E38F133435F4C4FD42A"};
	uint8_t keys4[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"};
	uint8_t data4[] = {"Sample message for keylen<blocklen, with truncated tag"};
	uint8_t expected4[] = {"FE3529565CD8E28C5FA79EAC9D8023B53B289D96"};

	key_len = 64;
	hex2ba(keys1, key, key_len);
	hex2ba(expected1, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA1);
	hmac.update(&hmac, data1, strlen(data1));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys2)/2;
	hex2ba(keys2, key, key_len);
	hex2ba(expected2, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA1);
	hmac.update(&hmac, data2, strlen(data2));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys3)/2;
	hex2ba(keys3, key, key_len);
	hex2ba(expected3, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA1);
	hmac.update(&hmac, data3, strlen(data3));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys4)/2;
	hex2ba(keys4, key, key_len);
	hex2ba(expected4, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA1);
	hmac.update(&hmac, data4, strlen(data4));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));


	printf("ALL TEST PASSED!\n");
	return 0;
}

