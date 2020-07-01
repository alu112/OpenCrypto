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
 * Implementation is based on NIST FIPS 202
 */
#include <stdlib.h>
#include "sha3.h"

REGISTER_HASH_ALGO(eHASH_SHA3_224, sha3_224_init);
REGISTER_HASH_ALGO(eHASH_SHA3_256, sha3_256_init);
REGISTER_HASH_ALGO(eHASH_SHA3_384, sha3_384_init);
REGISTER_HASH_ALGO(eHASH_SHA3_512, sha3_512_init);

static void sha3_run(uint64_t state[5][5]);
static void sha3_update(sha3_ctx_t *ctx, uint8_t *data, size_t len);
static void sha3_final(sha3_ctx_t *ctx, uint8_t digest[]);

/* round constant */
const uint64_t keccak_rc[24] = {
	0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
	0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
	0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
	0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
	0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
	0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
	0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
	0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

/*
 * rotate constant table 2 in NIST.FIPS.202.pdf
 * rotc[x,y] = table2[x,y] % 64 
 */
const int keccak_rotc[5][5] = {
#define ZBITS 64 /* bit length of Z-coordinate */
	/* x=         0,         1,        2,         3,         4 */
	/* y=0 */ {  0%ZBITS,   1%ZBITS, 190%ZBITS,  28%ZBITS,  91%ZBITS},
	/* y=1 */ { 36%ZBITS, 300%ZBITS,   6%ZBITS,  55%ZBITS, 276%ZBITS},
	/* y=2 */ {  3%ZBITS,  10%ZBITS, 171%ZBITS, 153%ZBITS, 231%ZBITS},
	/* y=3 */ {105%ZBITS,  45%ZBITS,  15%ZBITS,  21%ZBITS, 136%ZBITS},
	/* y=4 */ {210%ZBITS,  66%ZBITS, 253%ZBITS, 120%ZBITS,  78%ZBITS}
};


static void sha3_run(uint64_t state[5][5])
{
	uint32_t x, y, r;
	uint64_t d, c[5], b[5][5];

	for (r=0; r<24; r++) {
		/* Theta */
		for (x=0; x<5; x++)  {
			c[x] = state[0][x] ^ state[1][x] ^ state[2][x] ^ state[3][x] ^ state[4][x];
		}
		for (x=0; x<5; x++) {
			d = c[(x + 4) % 5] ^ ROTL64(c[(x + 1) % 5], 1);
			for (y=0; y<5; y++) {
				state[y][x] ^= d;
			}
		}

		/* Rho_Pi */
		for (x=0; x<5; x++) {
			for (y=0; y<5; y++) {
				b[(2*x + 3*y) % 5][y] = ROTL64(state[y][x], keccak_rotc[y][x]);
			}
		}

		/* Chi */
		for (x=0; x<5; x++) {
			for (y=0; y<5; y++) {
				state[y][x] = b[y][x] ^ (~b[y][(x+1)%5] & b[y][(x+2)%5]);
			}
		}

		/* Iota */
		state[0][0] ^= keccak_rc[r];
	}
}

static void sha3_init (sha3_ctx_t *ctx, uint32_t md_len, void (*init)(sha3_ctx_t *))
{
	memset (ctx,0,sizeof(*ctx));
	ctx->init     = init;
	ctx->update   = sha3_update;
	ctx->final    = sha3_final;
	ctx->buf_len  = 0;
	/* table 1.1 of Understanding-Cryptography-Keccak.pdf */
	/* md_len is c/2, buf_size is r */
	ctx->buf_size = (1600 - 2*md_len) / 8;
	ctx->md_len   = md_len;
}

void sha3_224_init (sha3_ctx_t *ctx)
{
	sha3_init(ctx, SHA224_DIGEST_LENGTH, sha3_224_init);
}

void sha3_256_init (sha3_ctx_t *ctx)
{
	sha3_init(ctx, SHA256_DIGEST_LENGTH, sha3_256_init);
}

void sha3_384_init (sha3_ctx_t *ctx)
{
	sha3_init(ctx, SHA384_DIGEST_LENGTH, sha3_384_init);
}

void sha3_512_init (sha3_ctx_t *ctx)
{
	sha3_init(ctx, SHA512_DIGEST_LENGTH, sha3_512_init);
}

static void sha3_update(sha3_ctx_t *ctx, uint8_t *data, size_t len)
{
	size_t i;
	uint8_t *state;

	state = (uint8_t *)ctx->state + ctx->buf_len;
	for (i=0; i<len; i++) {
		*state++ ^= *data++;
		if (++ctx->buf_len >= ctx->buf_size) {
			sha3_run(ctx->state);
			ctx->buf_len = 0;
			state = (uint8_t *)ctx->state;
		}
	}
}

static void sha3_final(sha3_ctx_t *ctx, uint8_t digest[])
{
	uint8_t padding[5*5*sizeof(uint64_t)];
	int n;

	n = ctx->buf_size - ctx->buf_len;
	memset(padding, 0, n);
	padding[0] = 0x06; /* put 0x01 here for Keccak */
	/* 0x06 and 0x80 might in the same byte */
	padding[n - 1] |= 0x80;

	sha3_update(ctx, padding, ctx->buf_size - ctx->buf_len);

	memcpy(digest, ctx->state, ctx->md_len/8);

	ctx->init(ctx);
}


void shake128_init(sha3_ctx_t *ctx)
{
	sha3_init(ctx, 128, shake128_init);
}

void shake256_init(sha3_ctx_t *ctx)
{
	sha3_init(ctx, 256, shake256_init);
}

void shake_update(sha3_ctx_t *ctx, uint8_t *data, size_t len)
{
	sha3_update(ctx, data, len);
}

void shake_xof(sha3_ctx_t *ctx)
{
	        uint8_t padding[5*5*sizeof(uint64_t)];
        int n;

        n = ctx->buf_size - ctx->buf_len;
        memset(padding, 0, n);
        padding[0] = 0x1F;
        /* 0x1F and 0x80 might in the same byte */
        padding[n - 1] |= 0x80;
	/* trigger sha3_run() */
        sha3_update(ctx, padding, ctx->buf_size - ctx->buf_len);

//        memcpy(digest, ctx->state, ctx->md_len/8);

//        ctx->init(ctx);

/*
	uint8_t byte;

	byte = 0x1F;
	sha3_update(ctx, &byte, 1);

	byte = 0x00;
	while (ctx->buf_len != ctx->buf_size - 1)
		sha3_update(ctx, &byte, 1);

	byte = 0x80;
	sha3_update(ctx, &byte, 1);
*/
	ctx->buf_len = 0;
}

void shake_out(sha3_ctx_t *ctx, uint8_t out[], size_t len)
{
	uint8_t *state;

	state = (uint8_t *)ctx->state + ctx->buf_len;

	for ( ; len; len--) {
		if (ctx->buf_len >= ctx->buf_size) {
			sha3_run(ctx->state);
			ctx->buf_len = 0;
			state = (uint8_t *)ctx->state;
		}
		*out++ = *state++;
		ctx->buf_len++;
	}
}

