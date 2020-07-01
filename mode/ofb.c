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
#include <string.h>
#include "cipher-mode.h"
#include "sha-common.h"


static size_t ofb_encrypt(cipher_ctx_t *ctx, uint8_t *buf, size_t len)
{
	size_t i, j, k;
	int blklen = ctx->cipher->blklen / 8;

	if (ctx->pad)
		len = ctx->pad->pad(buf, blklen, len);

	for (i=0; i<len; i+=blklen) {
		ctx->cipher->encrypt(ctx->cipher, ctx->iv, 1);
		if (len - i < blklen) k = len - i;
		else k = blklen;
		for (j=0; j<k; j++)
			*buf++ ^= ctx->iv[j];
	}

	return len;
}

static size_t ofb_decrypt(cipher_ctx_t *ctx, uint8_t *buf, size_t len)
{
	size_t i, j, k;
	int blklen = ctx->cipher->blklen / 8;

	for (i=0; i<len; i+=blklen) {
		ctx->cipher->encrypt(ctx->cipher, ctx->iv, 1);
		if (len - i < blklen) k = len - i;
		else k = blklen;
		for (j=0; j<k; j++)
			*buf++ ^= ctx->iv[j];
	}

	if (ctx->pad)
		i = ctx->pad->unpad(buf - blklen, blklen);
	else
		i = 0;

	return len - i;
}

void ofb_init(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *nounce)
{
	assert(ctx);
	assert(blk_ctx);
	if (pad) {
		assert(pad->pad);
		assert(pad->unpad);
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->init    = ofb_init;
	ctx->encrypt = ofb_encrypt;
	ctx->decrypt = ofb_decrypt;
	ctx->pad     = pad;
	ctx->cipher  = blk_ctx;
	ctx->ivlen   = blk_ctx->blklen / 8;
	if (nounce)
		memcpy(ctx->iv, nounce, ctx->ivlen);
}

