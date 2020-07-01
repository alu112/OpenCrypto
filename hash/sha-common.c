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

uint32_t swap32(uint32_t n)
{
	return (n << 24) | ((n & 0xff00) << 8) | ((n >> 8) & 0xff00) | (n >> 24);
}

uint64_t swap64(uint64_t n)
{
	return (uint64_t)swap32(n)<<32 | swap32(n >> 32);
}

uint128_t swap128(uint128_t n)
{
	return (uint128_t)swap64(n)<<64 | swap64(n >> 64);
}

/* hex string to byte byte array */
int hex2ba(uint8_t *hexstring, uint8_t *byte_array, int max_bytes)
{
	int bytes, len;
	uint8_t hex[4];

	assert(hexstring);
	assert(byte_array);
	assert(max_bytes > 0);

	memset(hex, 0, sizeof(hex));
	memset(byte_array, 0, max_bytes);

	while(*hexstring == ' ') hexstring++;

	if (!strncmp(hexstring, "0x", 2) || !strncmp(hexstring, "0X", 2))
		hexstring += 2;

	bytes = (strlen(hexstring) + 1) / 2;
	if (!bytes) return 0;
	len = bytes = bytes < max_bytes ? bytes : max_bytes;

	if (strlen(hexstring) & 1) {
		hex[0] = '0';
		hex[1] = *hexstring++;
		hex[2] = '\0';
		*byte_array++ = strtoul(hex, 0, 16);
		len--;
	}
	for (; len; len--) {
		memcpy(hex, hexstring, 2);
		hexstring += 2;
		*byte_array++ = strtoul(hex, 0, 16);
	}
	return bytes;
}

/*
 * byte array to hexstring
 * hex buffer must be at least 2n+1 bytes long
 */
uint8_t *ba2hex(uint8_t *bytes, int nbytes, uint8_t *hex)
{
	int i;
	for (i=0; i<nbytes; i++)
		sprintf(&hex[2*i], "%02x", bytes[i]);
	return hex;
}

int hash_init(enum hash_id hash_id, sha_ctx_t *sha)
{
	int result = -1;
	hash_algo_t *p = &__start_hash_algo;

	for ( ; p < &__stop_hash_algo; p++) {
		if (hash_id == p->hash_id) {
			p->init(sha);
			result = 0;
			break;
		}
	}
	return result;
}

