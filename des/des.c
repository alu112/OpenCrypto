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

/* http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "des.h"

#define B0   (1UL<<63)
#define B0B1 (3UL<<62)

typedef enum {ip, p, fp, exp, pc1, pc2} operation_t;

static inline void setbit(uint64_t *in64, uint64_t *out64, int from, int to);
static void permutation(uint64_t *in, uint64_t *out, operation_t op);
static void sbox(uint64_t *in48, uint64_t *out32);
static void key_schedule(uint64_t *key64, uint64_t *keyset48);
static void cipher(uint64_t *keyset48, uint64_t *block, int mode);
static void swap_u64(uint64_t *u64);


/* zero-based tables */
static const int initial_permutation_table[64] = {
	57, 49, 41, 33, 25, 17,  9,  1,
	59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5,
	63, 55, 47, 39, 31, 23, 15,  7,
	56, 48, 40, 32, 24, 16,  8,  0,
	58, 50, 42, 34, 26, 18, 10,  2,
	60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6
};
static const int final_permutation_table[64] = {
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25,
	32,  0, 40,  8, 48, 16, 56, 24
};
static const int expansion_table[48] = {
	31,  0,  1,  2,  3,  4,
	 3,  4,  5,  6,  7,  8,
	 7,  8,  9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31,  0
};
static const int p_permutation_table[32] =
{
	15,  6, 19, 20, 28, 11, 27, 16,
	 0, 14, 22, 25,  4, 17, 30,  9,
	 1,  7, 23, 13, 31, 26,  2,  8,
	18, 12, 29,  5, 21, 10,  3, 24
};
static const int pc1_permutation_table[56] =
{
	56, 48, 40, 32, 24, 16,  8,  0,
	57, 49, 41, 33, 25, 17,  9,  1,
	58, 50, 42, 34, 26, 18, 10,  2,
	59, 51, 43, 35, 62, 54, 46, 38,
	30, 22, 14,  6, 61, 53, 45, 37,
	29, 21, 13,  5, 60, 52, 44, 36,
	28, 20, 12,  4, 27, 19, 11,  3
};
static const int pc2_permutation_table[48] =
{
	13, 16, 10, 23,  0,  4,  2, 27,
	14,  5, 20,  9, 22, 18, 11,  3,
	25,  7, 15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54, 29, 39,
	50, 44, 32, 47, 43, 48, 38, 55,
	33, 52, 45, 41, 49, 35, 28, 31
};

/* 
 * sbox table re-organized as follow:
 * the original 6-bit index is rccccr
 *     which r is for row number
 *           c is for column number
 * this table is organized as a one-dimension
 * array, the idex is the 6-bit number
 */
static const uint8_t sbox_table[][64] =
{
	{
		14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
		 3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
		 4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
		15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13
	},
	{
		15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
		 9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
		 0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
		 5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9
	},
	{
		10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
		 1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
		13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
		11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12
	},
	{
		 7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
		 1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
		10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
		15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14
	},
	{
		 2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
		 8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
		 4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
		15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3
	},
	{
		12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
		 0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
		 9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
		 7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13
	},
	{
		 4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
		 3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
		 1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
		10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12
	},
	{
		13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
		10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
		 7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
		 0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
	}
};

/* bit0 is left, msbit */
static inline void setbit(uint64_t *in64, uint64_t *out64, int from, int to)
{
	*out64 |= ((*in64 >> (63-from)) & 1UL) << (63 - to);
}

static void permutation(uint64_t *in, uint64_t *out, operation_t op)
{
	int i, n;
	const int *table;

	switch(op) {
		case  ip: table = initial_permutation_table; n = 64; break;
		case   p: table = p_permutation_table;       n = 32; break;
		case  fp: table = final_permutation_table;   n = 64; break;
		case exp: table = expansion_table;           n = 48; break;
		case pc1: table = pc1_permutation_table;     n = 56; break;
		case pc2: table = pc2_permutation_table;     n = 48; break;
	}

	*out = 0;
	for (i=0; i<n; i++)
		setbit(in, out, table[i],  i);
}

static void sbox(uint64_t *in48, uint64_t *out32)
{
	int i;
	uint64_t u64;

	*out32 = 0UL;
	for (i=0; i<8; i++) {
		/* assign from uint8_t to uint64_t, expand to 64 bit */
		u64 = sbox_table[i][*in48 >> (64 - 6 - 6 * i)  & 0x3f];
		*out32 |= u64 << (64 - 4 - 4 * i);
	}
}

static void key_schedule(uint64_t *key64, uint64_t *keyset48)
{
	const int shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	int i;
	uint64_t key56, bitmask;

	permutation(key64, &key56, pc1);

	for (i=0; i<16; i++) {
		bitmask = shifts[i] == 1 ?  (B0 | B0>>28) : (B0B1 | B0B1>>28);
		key56 = (key56 & ~bitmask) << shifts[i] | (key56 & bitmask) >> (28 - shifts[i]);
		permutation(&key56, &keyset48[i], pc2);
	}
}

static void cipher(uint64_t *keyset48, uint64_t *block, int mode)
{
	int i;
	uint64_t x, f, l, r;

	permutation(block, &x, ip);

	l = x & 0xffffffff00000000UL;
	r = x << 32 & 0xffffffff00000000UL;

	for (i=0; i<16; i++) {
		/* the Feistel function */
		/* x is 48 bits */
		permutation(&r, &x, exp);
		/* temp use f as 48 bits */
		if (mode == DES_DECRYPT)
			f = x ^ keyset48[15-i];
		else
			f = x ^ keyset48[i];
		/* x is 32 bits after sbox */
		sbox(&f, &x);
		permutation(&x, &f, p);
		/* f is the Feistel function output, 32 bits */
		x = l;
		l = r;
		r = x ^ f;
	}

	x = r | l >> 32;

	permutation(&x, block, fp);
}

static int key_check(uint64_t *key64)
{
	int i, j, n;
	union {
		uint64_t u64;
		uint8_t  u8[8];
	} key;

	key.u64 = *key64;

	for (i=0; i<8; i++) {
		for (n=j=0; j<8; j++) {
			n ^= key.u8[i] & 1 << j ? 1 : 0;
		}
		if (!n) {
			printf("key parity check FAILED!\n");
			return 1;
		}
	}
	return 0;
}

static void swap_u64(uint64_t *u64)
{
	*u64 = *u64 << 32 | *u64 >> 32;
	*u64 = (*u64 & 0x0000ffff0000ffffUL) << 16 | (*u64 & 0xffff0000ffff0000UL) >> 16;
	*u64 = (*u64 & 0x00ff00ff00ff00ffUL) << 8  | (*u64 & 0xff00ff00ff00ff00UL) >> 8;
}

static void des_encrypt(des_ctx_t *ctx, uint8_t block[], size_t n)
{
	while (n--) {
		swap_u64((uint64_t *)block);
		cipher(ctx->keyset48, (uint64_t *)block, DES_ENCRYPT);
		swap_u64((uint64_t *)block);
		block += 8;
	}
}

static void des_decrypt(des_ctx_t *ctx, uint8_t block[], size_t n)
{
	while (n--) {
		swap_u64((uint64_t *)block);
		cipher(ctx->keyset48, (uint64_t *)block, DES_DECRYPT);
		swap_u64((uint64_t *)block);
		block += 8;
	}
}

static void tdes_encrypt(tdes_ctx_t *ctx, uint8_t block[], size_t nblocks)
{
	while (nblocks--) {
		swap_u64((uint64_t *)block);
		cipher(ctx->keyset48[0], (uint64_t *)block, DES_ENCRYPT);
		cipher(ctx->keyset48[1], (uint64_t *)block, DES_DECRYPT);
		cipher(ctx->keyset48[2], (uint64_t *)block, DES_ENCRYPT);
		swap_u64((uint64_t *)block);
		block += 8;
	}
}

static void tdes_decrypt(tdes_ctx_t *ctx, uint8_t block[], size_t nblocks)
{
	while (nblocks--) {
		swap_u64((uint64_t *)block);
		cipher(ctx->keyset48[2], (uint64_t *)block, DES_DECRYPT);
		cipher(ctx->keyset48[1], (uint64_t *)block, DES_ENCRYPT);
		cipher(ctx->keyset48[0], (uint64_t *)block, DES_DECRYPT);
		swap_u64((uint64_t *)block);
		block += 8;
	}
}

int  des_init(des_ctx_t *ctx, uint8_t *key)
{
	assert(ctx);
	assert(key);
	memset(ctx, 0, sizeof(*ctx));
	ctx->init = des_init;
	ctx->encrypt = des_encrypt;
	ctx->decrypt = des_decrypt;
	ctx->keylen = 64;
	ctx->blklen = 64;
	if (key_check((uint64_t *)key)) return -1;
	memcpy(ctx->key, key, ctx->keylen/8);
	swap_u64((uint64_t *)key);
	key_schedule((uint64_t *)key, ctx->keyset48);
	return 0;
}

int tdes_init(tdes_ctx_t *ctx, uint8_t *keys, int keylen)
{
	int i;
	uint64_t key64;
	assert(ctx);
	assert(keys);

	memset(ctx, 0, sizeof(*ctx));
	ctx->init    = tdes_init;
	ctx->encrypt = tdes_encrypt;
	ctx->decrypt = tdes_decrypt;
	ctx->keylen = 64;
	ctx->blklen = 64;
	switch(keylen) {
		case 64: /* key1 = key2 = key3 */
			memcpy(ctx->key[0], keys, sizeof(uint64_t));
			memcpy(ctx->key[1], keys, sizeof(uint64_t));
			memcpy(ctx->key[2], keys, sizeof(uint64_t));
			break;
		case 128: /* key1, key2 independent, key3 = key1 */
			memcpy(ctx->key[0], keys, sizeof(uint64_t));
			memcpy(ctx->key[1], keys+sizeof(uint64_t), sizeof(uint64_t));
			memcpy(ctx->key[2], keys, sizeof(uint64_t));
			break;
		case 192: /* key1, key2, key3 all independent */
			memcpy(ctx->key[0], keys, sizeof(uint64_t));
			memcpy(ctx->key[1], keys+sizeof(uint64_t), sizeof(uint64_t));
			memcpy(ctx->key[2], keys+2*sizeof(uint64_t), sizeof(uint64_t));
			break;
		default:
			return -1;
	}
	if (key_check((uint64_t *)ctx->key[0])) return -1;
	if (key_check((uint64_t *)ctx->key[1])) return -2;
	if (key_check((uint64_t *)ctx->key[2])) return -3;
	for (i=0; i<3; i++) {
		memcpy(&key64, ctx->key[i], sizeof(uint64_t));
		swap_u64((uint64_t *)&key64);
		key_schedule(&key64, ctx->keyset48[i]);
	}
	return 0;
}
