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
 * Implementation is based on NIST FIPS 180-4
 */
#include <stdlib.h>
#include "sha1.h"

REGISTER_HASH_ALGO(eHASH_SHA1, sha1_init);

static void sha1_update(sha1_ctx_t *ctx, uint8_t *data, size_t len);
static void sha1_final(sha1_ctx_t *ctx, uint8_t digest[SHA1_DIGEST_LENGTH / 8]);

const uint32_t K1 = 0x5A827999;
const uint32_t K2 = 0x6ED9EBA1;
const uint32_t K3 = 0x8F1BBCDC;
const uint32_t K4 = 0xCA62C1D6;

const uint32_t H0[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};


#define Ch(x,y,z)     (((x) & (y)) ^ ((~(x)) & (z)))
#define Parity(x,y,z) ((x) ^ (y) ^ (z))
#define Maj(x,y,z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define W(I) (x[I&15] = ROTL32(x[I&15] ^ x[(I-14)&15] ^ x[(I-8)&15] ^ x[(I-3)&15], 1))

#define R(A,B,C,D,E,Func,K,W)        \
	do {                         \
		E += Func( B, C, D ) + ROTL32( A, 5 ) + W + K; \
		B = ROTL32( B, 30 );   \
	} while(0)


static void sha1_run(uint32_t state[5], uint8_t data[SHA1_BUF_SIZE])
{
	uint32_t i, a, b, c, d, e, x[16];

	memcpy(x, data, sizeof(x)); /* avoid alignment issue */
	for (i=0; i<ARRAY_SIZE(x); i++)
		x[i] = swap32(x[i]);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	R( a, b, c, d, e, Ch,     K1, x[ 0] );
	R( e, a, b, c, d, Ch,     K1, x[ 1] );
	R( d, e, a, b, c, Ch,     K1, x[ 2] );
	R( c, d, e, a, b, Ch,     K1, x[ 3] );
	R( b, c, d, e, a, Ch,     K1, x[ 4] );
	R( a, b, c, d, e, Ch,     K1, x[ 5] );
	R( e, a, b, c, d, Ch,     K1, x[ 6] );
	R( d, e, a, b, c, Ch,     K1, x[ 7] );
	R( c, d, e, a, b, Ch,     K1, x[ 8] );
	R( b, c, d, e, a, Ch,     K1, x[ 9] );
	R( a, b, c, d, e, Ch,     K1, x[10] );
	R( e, a, b, c, d, Ch,     K1, x[11] );
	R( d, e, a, b, c, Ch,     K1, x[12] );
	R( c, d, e, a, b, Ch,     K1, x[13] );
	R( b, c, d, e, a, Ch,     K1, x[14] );
	R( a, b, c, d, e, Ch,     K1, x[15] );
	R( e, a, b, c, d, Ch,     K1, W(16) );
	R( d, e, a, b, c, Ch,     K1, W(17) );
	R( c, d, e, a, b, Ch,     K1, W(18) );
	R( b, c, d, e, a, Ch,     K1, W(19) );
	R( a, b, c, d, e, Parity, K2, W(20) );
	R( e, a, b, c, d, Parity, K2, W(21) );
	R( d, e, a, b, c, Parity, K2, W(22) );
	R( c, d, e, a, b, Parity, K2, W(23) );
	R( b, c, d, e, a, Parity, K2, W(24) );
	R( a, b, c, d, e, Parity, K2, W(25) );
	R( e, a, b, c, d, Parity, K2, W(26) );
	R( d, e, a, b, c, Parity, K2, W(27) );
	R( c, d, e, a, b, Parity, K2, W(28) );
	R( b, c, d, e, a, Parity, K2, W(29) );
	R( a, b, c, d, e, Parity, K2, W(30) );
	R( e, a, b, c, d, Parity, K2, W(31) );
	R( d, e, a, b, c, Parity, K2, W(32) );
	R( c, d, e, a, b, Parity, K2, W(33) );
	R( b, c, d, e, a, Parity, K2, W(34) );
	R( a, b, c, d, e, Parity, K2, W(35) );
	R( e, a, b, c, d, Parity, K2, W(36) );
	R( d, e, a, b, c, Parity, K2, W(37) );
	R( c, d, e, a, b, Parity, K2, W(38) );
	R( b, c, d, e, a, Parity, K2, W(39) );
	R( a, b, c, d, e, Maj,    K3, W(40) );
	R( e, a, b, c, d, Maj,    K3, W(41) );
	R( d, e, a, b, c, Maj,    K3, W(42) );
	R( c, d, e, a, b, Maj,    K3, W(43) );
	R( b, c, d, e, a, Maj,    K3, W(44) );
	R( a, b, c, d, e, Maj,    K3, W(45) );
	R( e, a, b, c, d, Maj,    K3, W(46) );
	R( d, e, a, b, c, Maj,    K3, W(47) );
	R( c, d, e, a, b, Maj,    K3, W(48) );
	R( b, c, d, e, a, Maj,    K3, W(49) );
	R( a, b, c, d, e, Maj,    K3, W(50) );
	R( e, a, b, c, d, Maj,    K3, W(51) );
	R( d, e, a, b, c, Maj,    K3, W(52) );
	R( c, d, e, a, b, Maj,    K3, W(53) );
	R( b, c, d, e, a, Maj,    K3, W(54) );
	R( a, b, c, d, e, Maj,    K3, W(55) );
	R( e, a, b, c, d, Maj,    K3, W(56) );
	R( d, e, a, b, c, Maj,    K3, W(57) );
	R( c, d, e, a, b, Maj,    K3, W(58) );
	R( b, c, d, e, a, Maj,    K3, W(59) );
	R( a, b, c, d, e, Parity, K4, W(60) );
	R( e, a, b, c, d, Parity, K4, W(61) );
	R( d, e, a, b, c, Parity, K4, W(62) );
	R( c, d, e, a, b, Parity, K4, W(63) );
	R( b, c, d, e, a, Parity, K4, W(64) );
	R( a, b, c, d, e, Parity, K4, W(65) );
	R( e, a, b, c, d, Parity, K4, W(66) );
	R( d, e, a, b, c, Parity, K4, W(67) );
	R( c, d, e, a, b, Parity, K4, W(68) );
	R( b, c, d, e, a, Parity, K4, W(69) );
	R( a, b, c, d, e, Parity, K4, W(70) );
	R( e, a, b, c, d, Parity, K4, W(71) );
	R( d, e, a, b, c, Parity, K4, W(72) );
	R( c, d, e, a, b, Parity, K4, W(73) );
	R( b, c, d, e, a, Parity, K4, W(74) );
	R( a, b, c, d, e, Parity, K4, W(75) );
	R( e, a, b, c, d, Parity, K4, W(76) );
	R( d, e, a, b, c, Parity, K4, W(77) );
	R( c, d, e, a, b, Parity, K4, W(78) );
	R( b, c, d, e, a, Parity, K4, W(79) );

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

void sha1_init(sha1_ctx_t *ctx)
{
	memset (ctx,0,sizeof(*ctx));
	ctx->init     = sha1_init;
	ctx->update   = sha1_update;
	ctx->final    = sha1_final;
	ctx->total    = 0UL;
	ctx->buf_len  = 0;
	ctx->buf_size = SHA1_BUF_SIZE;
	ctx->md_len   = SHA1_DIGEST_LENGTH;
	memcpy(ctx->state, H0, sizeof(H0));
}

static void sha1_update(sha1_ctx_t *ctx, uint8_t *data, size_t len)
{
	size_t i;

	if (len + ctx->buf_len > SHA1_BUF_SIZE - 1) {
		i = SHA1_BUF_SIZE - ctx->buf_len;
		memcpy(&ctx->buffer[ctx->buf_len], data, i);
		sha1_run(ctx->state, ctx->buffer);
		for (; i+SHA1_BUF_SIZE-1<len; i+=SHA1_BUF_SIZE) {
			sha1_run(ctx->state, &data[i]);
		}
		ctx->buf_len = len - i;
		memcpy(&ctx->buffer, &data[i], ctx->buf_len);
	}
	else {
		memcpy(&ctx->buffer[ctx->buf_len], data, len);
		ctx->buf_len += len;
	}
	ctx->total += len;
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t digest[SHA1_DIGEST_LENGTH / 8])
{
	int i;
	uint8_t byte;
	uint64_t qw;

	qw = ctx->total * 8;
	byte = 0x80;
	sha1_update(ctx, &byte, 1);
	/*
	 * if after add byte 0x80, the ctx->buf_len >= 64 - sizeof(qw)
	 * the following while statement will triger an sha1_run
	 */
	byte = 0x00;
	while (ctx->buf_len != SHA1_BUF_SIZE - sizeof(qw))
		sha1_update(ctx, &byte, 1);

	qw = swap64(qw);
	sha1_update(ctx, (uint8_t *)&qw, sizeof(qw)); /* trigger sha1_run() */

	for (i=0; i<ARRAY_SIZE(ctx->state); i++)
		ctx->state[i] = swap32(ctx->state[i]);
	memcpy(digest, ctx->state, ctx->md_len/8);

	ctx->init(ctx);
}

