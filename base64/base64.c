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

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "base64.h"

static const uint8_t encoding_table[] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

static  const uint8_t decoding_table[] = 
{
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static const size_t padding_table[] = {0, 2, 1};

#if 0
void build_decoding_table() 
{
	int i, j;
	for (i = 0; i < 64; i++)
		decoding_table[encoding_table[i]] = i;
	for (i=0; i< 16; i++) {
		for (j=0; j<16;j++) {
			printf("%2d, ", decoding_table[i*16 + j]);
		}
		printf("\n");
	}
}
#endif

/* the length inlcudes a string terminator '\0' */
size_t base64_get_encoded_length(const uint8_t *data, size_t ilen)
{
	return 4 * ((ilen + 2) / 3) + 1;
}

size_t base64_get_decoded_length(const uint8_t *encoded)
{
	size_t ilen, decoded_length;

	ilen = strlen(encoded);
	if (ilen % 4) return 0;

	decoded_length = ilen / 4 * 3;
	if (encoded[ilen - 1] == '=') decoded_length--;
	if (encoded[ilen - 2] == '=') decoded_length--;
	return decoded_length;
}

/* don't support inplace encoding */
size_t base64_encode(const uint8_t *data, int ilen, uint8_t *encoded)
{
	size_t i, encoded_length;
	uint32_t u24;

	encoded_length = 4 * ((ilen + 2) / 3) + 1;

	for (i=0; i<ilen;) {

		u24 = i < ilen ? data[i++] : 0;
		u24 = (u24 << 8) | (i < ilen ? data[i++] : 0);
		u24 = (u24 << 8) | (i < ilen ? data[i++] : 0);

		*encoded++ = encoding_table[(u24 >> 3 * 6) & 0x3F];
		*encoded++ = encoding_table[(u24 >> 2 * 6) & 0x3F];
		*encoded++ = encoding_table[(u24 >> 1 * 6) & 0x3F];
		*encoded++ = encoding_table[(u24 >> 0 * 6) & 0x3F];
	}

	*encoded-- = '\0';
	for (i = 0; i < padding_table[ilen % 3]; i++)
		*encoded-- = '=';

	return encoded_length;
}

/* support inplace decoding */
size_t base64_decode(const uint8_t *encoded, uint8_t *plain)
{
	size_t i, j, ilen, decoded_length;
	uint32_t u32;

	ilen = strlen(encoded);
	if (ilen % 4) return 0;

	decoded_length = ilen / 4 * 3;
	if (encoded[ilen - 1] == '=') decoded_length--;
	if (encoded[ilen - 2] == '=') decoded_length--;

	for (i=0, j=0; i<ilen;) {

		u32 = decoding_table[encoded[i++]];
		u32 = (u32 << 8) | decoding_table[encoded[i++]];
		u32 = (u32 << 8) | decoding_table[encoded[i++]];
		u32 = (u32 << 8) | decoding_table[encoded[i++]];

		u32 = (u32 >> 6 & 0xFC0000) | (u32 >> 4 & 0x3F000) | (u32 >> 2 & 0xFC0) | (u32 & 0x3F);

		if (j < decoded_length) plain[j++] = *((uint8_t *)&u32 + 2);
		if (j < decoded_length) plain[j++] = *((uint8_t *)&u32 + 1);
		if (j < decoded_length) plain[j++] = *((uint8_t *)&u32 + 0);
	}

	return decoded_length;
}

