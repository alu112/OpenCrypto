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
 * echo -n "value" | openssl dgst -sha3-256 -hmac "key"
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac.h"

/*
 * test vectors from:
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-256.pdf 
 */


int main(int argc, char *argv[])
{
	hmac_ctx_t hmac;
	int len, key_len, exp_len;
	uint8_t key[256];
	uint8_t dgst[512/8];
	uint8_t expdgst[sizeof(dgst)];
	uint8_t data1[] = {"Sample message for keylen<blocklen"};
	uint8_t keys1[] = {
		"000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F"};
	uint8_t expected1[] = {
		"4fe8e202c4f058e8dddc23d8c34e4673"
		"43e23555e24fc2f025d598f558f67205"};
	uint8_t data2[] = {"Sample message for keylen=blocklen"};
	uint8_t keys2[] = {
		"000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F"
		"303132333435363738393A3B3C3D3E3F"
		"404142434445464748494a4b4c4d4e4f"
		"505152535455565758595a5b5c5d5e5f"
		"606162636465666768696a6b6c6d6e6f"
		"707172737475767778797a7b7c7d7e7f"
		"8081828384858687"};
	uint8_t expected2[] = {
		"68b94e2e538a9be4103bebb5aa016d47"
		"961d4d1aa906061313b557f8af2c3faa"};
	uint8_t data3[] = {"Sample message for keylen>blocklen"};
	uint8_t keys3[] = {
		"000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F"
		"303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F"
		"505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F"
		"707172737475767778797A7B7C7D7E7F"
		"808182838485868788898a8b8c8d8e8f"
		"909192939495969798999a9b9c9d9e9f"
		"a0a1a2a3a4a5a6a7"};
	uint8_t expected3[] = {
		"9bcf2c238e235c3ce88404e813bd2f3a"
		"97185ac6f238c63d6229a00b07974258"};
	uint8_t data4[] = {"Sample message for keylen<blocklen, with truncated tag"};
	uint8_t keys4[] = {
		"000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F"};
	uint8_t expected4[] = {
		"c8dc7148d8c1423aa549105dafdf9cad"
		"2941471b5c62207088e56ccf2dd80545"};

	key_len = hex2ba(keys1, key, sizeof(key));
	exp_len = hex2ba(expected1, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA3_256);
	hmac.update(&hmac, data1, strlen(data1));
	len = hmac.final(&hmac, dgst);
	assert(len == exp_len);
	assert(!memcmp(expdgst, dgst, len));

	key_len = hex2ba(keys2, key, sizeof(key));
	exp_len = hex2ba(expected2, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA3_256);
	hmac.update(&hmac, data2, strlen(data2));
	len = hmac.final(&hmac, dgst);
	assert(len == exp_len);
	assert(!memcmp(expdgst, dgst, len));

	key_len = hex2ba(keys3, key, sizeof(key));
	exp_len = hex2ba(expected3, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA3_256);
	hmac.update(&hmac, data3, strlen(data3));
	len = hmac.final(&hmac, dgst);
	assert(len == exp_len);
	assert(!memcmp(expdgst, dgst, len));

	key_len = hex2ba(keys4, key, sizeof(key));
	exp_len = hex2ba(expected4, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA3_256);
	hmac.update(&hmac, data4, strlen(data4));
	len = hmac.final(&hmac, dgst);
	assert(len == exp_len);
	assert(!memcmp(expdgst, dgst, len));


	printf("ALL TEST PASSED!\n");
	return 0;
}

