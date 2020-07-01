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

static size_t ecb_encrypt(cipher_ctx_t *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	int blklen = ctx->cipher->blklen / 8;

	if (ctx->pad)
		len = ctx->pad->pad(buf, blklen, len);
	else
		assert(len % blklen == 0);

	for (i=0; i<len; i+=blklen) {
		ctx->cipher->encrypt(ctx->cipher, buf, 1);
		buf += blklen;
	}
	return len;
}

static size_t ecb_decrypt(cipher_ctx_t *ctx, uint8_t *buf, size_t len)
{
	size_t i;
	int blklen = ctx->cipher->blklen / 8;

	assert(len % blklen == 0);

	for (i=0; i<len; i+=blklen) {
		ctx->cipher->decrypt(ctx->cipher, buf, 1);
		buf += blklen;
	}

	if (ctx->pad)
		i = ctx->pad->unpad(buf - blklen, blklen);
	else
		i = 0;

	return len - i;
}

void ecb_init(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv)
{
	assert(ctx);
	assert(blk_ctx);
	if (pad) {
		assert(pad->pad);
		assert(pad->unpad);
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->init    = ecb_init;
	ctx->encrypt = ecb_encrypt;
	ctx->decrypt = ecb_decrypt;
	ctx->pad     = pad;
	ctx->cipher  = blk_ctx;
	ctx->ivlen   = blk_ctx->blklen/8;
	if (iv)
		memcpy(ctx->iv, iv, ctx->ivlen);
}

