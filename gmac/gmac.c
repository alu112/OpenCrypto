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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "sha-common.h"
#include "cipher-mode.h"
#include "gmac.h"

#define MSB  (*(uint128_t *)"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x80")

static void inc_ctr32(uint8_t *ctr)
{
	register uint32_t u32;

	u32 = swap32(*(uint32_t *)ctr);
	*(uint32_t *)ctr = swap32(++u32);
}

static void xor128(uint128_t *src, uint128_t *dst)
{
	*dst ^= *src;
}

static void lshift128(uint128_t *u128)
{
	*u128 <<= 1;
}

static void rshift128(uint128_t *u128)
{
	*u128 >>= 1;
}

/* Multiplication in GF(2^128) */
static void mult128(uint128_t *x, uint128_t *y, uint128_t *z)
{
	const uint128_t R = *(uint128_t *)"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\xE1";
	uint128_t X, Z, v;
	int i;

	Z = 0;     /* Z[0] = 0 */
	X  = *x;
	v  = *y;   /* V[0] = Y */
	for (i = 0; i < 128; i++) {
		if (X & MSB) {
			/* Z[i + 1] = Z[i] XOR V[i] */
			xor128(&v, &Z);
		} else {
			/* Z[i + 1] = Z[i] */
		}
		lshift128(&X);
		if (v & 1) {
			/* V[i + 1] = (V[i] >> 1) XOR R */
			rshift128(&v);
			xor128((uint128_t *)&R, &v);
		} else {
			/* V[i + 1] = V[i] >> 1 */
			rshift128(&v);
		}
	}
	*z = Z;
}

static void ghash(uint128_t *h, uint8_t *x, uint128_t *y)
{
	uint128_t X;

	X = swap128(*(uint128_t *)x);
	xor128(&X, y);
	mult128(h, y, y);
}

static void gctr(gmac_ctx_t *ctx, uint8_t *x)
{
	uint8_t  ivctr[16];

	inc_ctr32(ctx->j0 + 12);
	memcpy(ivctr, ctx->j0, 16);

	ctx->cipher->encrypt(ctx->cipher, ivctr, 1);
	xor128((uint128_t *)ivctr, (uint128_t *)x);
}

static void gmac_encrypt(gmac_ctx_t *ctx, uint8_t x[], size_t xn, uint8_t tag[])
{
	uint8_t s[16], j0[16];
	size_t n;
	uint128_t y = ctx->aad;

	memcpy(j0, ctx->j0, 16);
	ctx->cipher->encrypt(ctx->cipher, j0, 1);

	n = xn / 16;
	while (n--) {
		gctr(ctx, x);
		ghash(&ctx->h, x, &y);
		x += 16;
	}
	if (xn % 16) {
		memcpy(s, x, xn % 16);
		gctr(ctx, s);
		memcpy(x, s, xn % 16);
		memset(s + xn % 16, 0, 16 - xn % 16);
		ghash(&ctx->h, s, &y);
	}

	*(uint64_t *)s = swap64(ctx->aad_len * 8);
	*(uint64_t *)(s+8) = swap64(xn * 8);
	ghash(&ctx->h, s, &y);
	*(uint128_t *)s = swap128(y);

	xor128((uint128_t *)j0, (uint128_t *)s);
	if (tag)
		memcpy(tag, s, ctx->tag_len);
}

static int gmac_decrypt(gmac_ctx_t *ctx, uint8_t x[], size_t xn, uint8_t tag[])
{
	uint8_t s[16], j0[16];
	size_t n;
	uint128_t y = ctx->aad;

	memcpy(j0, ctx->j0, 16);
	ctx->cipher->encrypt(ctx->cipher, j0, 1);

	n = xn / 16;
	while (n--) {
		ghash(&ctx->h, x, &y);
		gctr(ctx, x);
		x += 16;
	}
	if (xn % 16) {
		memcpy(s, x, xn % 16);
		memset(s + xn % 16, 0, 16 - xn % 16);
		ghash(&ctx->h, s, &y);
		gctr(ctx, s);
		memcpy(x, s, xn % 16);
	}

	*(uint64_t *)s = swap64(ctx->aad_len * 8);
	*(uint64_t *)(s+8) = swap64(xn * 8);
	ghash(&ctx->h, s, &y);
	*(uint128_t *)s = swap128(y);

	xor128((uint128_t *)j0, (uint128_t *)s);
	return memcmp(tag, s, ctx->tag_len);
}

/* the aes_ctr->init must be set before call gmac_init() */
int  gmac_init(gmac_ctx_t *ctx, uint8_t *iv, size_t iv_len, uint8_t *aad, size_t aad_len, int tag_len, blk_ctx_t *cipher)
{
	uint8_t s[16];
	uint128_t y;

	assert(ctx);
	assert(iv);
	assert(aad);
	assert(cipher);
	assert(cipher->init);

	memset(ctx, 0, sizeof(*ctx));
	ctx->init    = gmac_init;
	ctx->encrypt = gmac_encrypt;
	ctx->decrypt = gmac_decrypt;
	ctx->cipher  = cipher;
	/* save length of tag */
	ctx->tag_len = tag_len;
	/* get hash subkey */
	ctx->h = 0;
	cipher->encrypt(cipher, (uint8_t *)&ctx->h, 1);
	ctx->h = swap128(ctx->h);
	/* prepare J0, the ICB  */
	ctx->iv_len = iv_len;
	if (iv_len == 12) { /* 96 bits */
		memset(ctx->j0, 0, sizeof(ctx->j0));
		ctx->j0[15] = 1;
		memcpy(ctx->j0, iv, iv_len);
	}
	else {
		iv_len /= 16;
		y = 0;
		while (iv_len--) {
			ghash(&ctx->h, iv, &y);
			iv += 16;
		}
		if (ctx->iv_len % 16) {
			memset(s, 0, 16);
			memcpy(s, iv, ctx->iv_len % 16);
			ghash(&ctx->h, s, &y);
		}
		memset(s, 0, 16);
		*(uint64_t *)(s + 8) = swap64(ctx->iv_len * 8);
		ghash(&ctx->h, s, &y);
		*(uint128_t *)ctx->j0 = swap128(y);
	}
	/* hash auth_data */
	ctx->aad_len = aad_len;
	aad_len /= 16;
	y = 0;
	while (aad_len--) {
		ghash(&ctx->h, aad, &y);
		aad += 16;
	}
	if (ctx->aad_len % 16) {
		memset(s, 0, 16);
		memcpy(s, aad, ctx->aad_len % 16);
		ghash(&ctx->h, s, &y);
	}
	ctx->aad = y;
}

