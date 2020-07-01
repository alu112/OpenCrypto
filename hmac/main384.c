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
 * echo -n "value" | openssl dgst -sha384 -hmac "key"
 */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac.h"

/*
 * test vectors from:
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA384.pdf
 */

int main(int argc, char *argv[])
{
	hmac_ctx_t hmac;
	int len, key_len;
	uint8_t key[128*2];
	uint8_t dgst[384/8];
	uint8_t expdgst[sizeof(dgst)];
	uint8_t keys1[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"};
	uint8_t data1[] = {"Sample message for keylen=blocklen"};
	uint8_t expected1[] = {"63C5DAA5E651847CA897C95814AB830BEDEDC7D25E83EEF9195CD45857A37F448947858F5AF50CC2B1B730DDF29671A9"};
	uint8_t keys2[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"};
	uint8_t data2[] = {"Sample message for keylen<blocklen"};
	uint8_t expected2[] = {"6EB242BDBB582CA17BEBFA481B1E23211464D2B7F8C20B9FF2201637B93646AF5AE9AC316E98DB45D9CAE773675EEED0"};
	uint8_t keys3[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"};
	uint8_t data3[] = {"Sample message for keylen=blocklen"};
	uint8_t expected3[] = {"5B664436DF69B0CA22551231A3F0A3D5B4F97991713CFA84BFF4D0792EFF96C27DCCBBB6F79B65D548B40E8564CEF594"};
	uint8_t keys4[] = {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"};
	uint8_t data4[] = {"Sample message for keylen<blocklen, with truncated tag"};
	uint8_t expected4[] = {"C48130D3DF703DD7CDAA56800DFBD2BA2458320E6E1F98FEC8AD9F57F43800DF3615CEB19AB648E1ECDD8C730AF95C8A"};

	key_len = 128;
	hex2ba(keys1, key, key_len);
	hex2ba(expected1, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA384);
	hmac.update(&hmac, data1, strlen(data1));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys2)/2;
	hex2ba(keys2, key, key_len);
	hex2ba(expected2, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA384);
	hmac.update(&hmac, data2, strlen(data2));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys3)/2;
	hex2ba(keys3, key, key_len);
	hex2ba(expected3, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA384);
	hmac.update(&hmac, data3, strlen(data3));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));

	key_len = strlen(keys4)/2;
	hex2ba(keys4, key, key_len);
	hex2ba(expected4, expdgst, sizeof(dgst));
	hmac_init(&hmac, key, key_len, eHASH_SHA384);
	hmac.update(&hmac, data4, strlen(data4));
	len = hmac.final(&hmac, dgst);
	assert(!memcmp(expdgst, dgst, len));


	printf("ALL TEST PASSED!\n");
	return 0;
}

