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
#include "sha256.h"

REGISTER_HASH_ALGO(eHASH_SHA224, sha224_init);
REGISTER_HASH_ALGO(eHASH_SHA256, sha256_init);

static void sha256_run(uint32_t state[8], uint8_t data[SHA256_BUF_SIZE]);
static void sha256_update(sha256_ctx_t *ctx, uint8_t *data, size_t len);
static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[]);

static const uint32_t K[64] = {
	0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
	0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
	0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
	0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
	0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
	0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
	0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
	0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
	0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
	0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
	0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
	0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
	0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
	0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
	0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
	0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static const uint32_t H0_224[] = {
	0xc1059ed8U,0x367cd507U,0x3070dd17U,0xf70e5939U,
	0xffc00b31U,0x68581511U,0x64f98fa7U,0xbefa4fa4U
};

static const uint32_t H0_256[] = {
	0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
	0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
};


#define Ch(x,y,z)     (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0(x)     (ROTR32((x), 2) ^ ROTR32((x),13) ^ ROTR32((x),22))
#define Sigma1(x)     (ROTR32((x), 6) ^ ROTR32((x),11) ^ ROTR32((x),25))
#define sigma0(x)     (ROTR32((x), 7) ^ ROTR32((x),18) ^ SHR((x), 3))
#define sigma1(x)     (ROTR32((x),17) ^ ROTR32((x),19) ^ SHR((x),10))


#define W(t) (x[t&15] = sigma1(x[(t-2)&15]) + x[(t-7)&15] + sigma0(x[(t-15)&15]) + x[t&15])


#define R(A,B,C,D,E,F,G,H,K,W,T1,T2)                      \
	do {                                              \
		T1 = H + Sigma1(E) + Ch(E, F, G) + K + W; \
		T2 = Sigma0(A) + Maj(A, B, C);            \
		D += T1;                                  \
		H  = T1 + T2;                             \
	} while(0)


static void sha256_run(uint32_t state[8], uint8_t data[SHA256_BUF_SIZE])
{
	uint32_t i, a, b, c, d, e, f, g, h, x[16], t1, t2;

	memcpy(x, data, sizeof(x)); /* avoid alignment issue */
	for (i=0; i<16; i++)
		x[i] = swap32(x[i]);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	R( a, b, c, d, e, f, g, h, K[ 0], x[ 0], t1, t2 );
	R( h, a, b, c, d, e, f, g, K[ 1], x[ 1], t1, t2 );
	R( g, h, a, b, c, d, e, f, K[ 2], x[ 2], t1, t2 );
	R( f, g, h, a, b, c, d, e, K[ 3], x[ 3], t1, t2 );
	R( e, f, g, h, a, b, c, d, K[ 4], x[ 4], t1, t2 );
	R( d, e, f, g, h, a, b, c, K[ 5], x[ 5], t1, t2 );
	R( c, d, e, f, g, h, a, b, K[ 6], x[ 6], t1, t2 );
	R( b, c, d, e, f, g, h, a, K[ 7], x[ 7], t1, t2 );
	R( a, b, c, d, e, f, g, h, K[ 8], x[ 8], t1, t2 );
	R( h, a, b, c, d, e, f, g, K[ 9], x[ 9], t1, t2 );
	R( g, h, a, b, c, d, e, f, K[10], x[10], t1, t2 );
	R( f, g, h, a, b, c, d, e, K[11], x[11], t1, t2 );
	R( e, f, g, h, a, b, c, d, K[12], x[12], t1, t2 );
	R( d, e, f, g, h, a, b, c, K[13], x[13], t1, t2 );
	R( c, d, e, f, g, h, a, b, K[14], x[14], t1, t2 );
	R( b, c, d, e, f, g, h, a, K[15], x[15], t1, t2 );
	R( a, b, c, d, e, f, g, h, K[16], W(16), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[17], W(17), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[18], W(18), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[19], W(19), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[20], W(20), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[21], W(21), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[22], W(22), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[23], W(23), t1, t2 );
	R( a, b, c, d, e, f, g, h, K[24], W(24), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[25], W(25), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[26], W(26), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[27], W(27), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[28], W(28), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[29], W(29), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[30], W(30), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[31], W(31), t1, t2 );
	R( a, b, c, d, e, f, g, h, K[32], W(32), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[33], W(33), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[34], W(34), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[35], W(35), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[36], W(36), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[37], W(37), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[38], W(38), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[39], W(39), t1, t2 );
	R( a, b, c, d, e, f, g, h, K[40], W(40), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[41], W(41), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[42], W(42), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[43], W(43), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[44], W(44), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[45], W(45), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[46], W(46), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[47], W(47), t1, t2 );
	R( a, b, c, d, e, f, g, h, K[48], W(48), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[49], W(49), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[50], W(50), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[51], W(51), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[52], W(52), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[53], W(53), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[54], W(54), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[55], W(55), t1, t2 );
	R( a, b, c, d, e, f, g, h, K[56], W(56), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[57], W(57), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[58], W(58), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[59], W(59), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[60], W(60), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[61], W(61), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[62], W(62), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[63], W(63), t1, t2 );

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

void sha224_init (sha256_ctx_t *ctx)
{
	memset (ctx,0,sizeof(*ctx));
	ctx->init     = sha224_init;
	ctx->update   = sha256_update;
	ctx->final    = sha256_final;
	ctx->total    = 0UL;
	ctx->buf_len  = 0;
	ctx->buf_size = SHA256_BUF_SIZE;
	ctx->md_len   = SHA224_DIGEST_LENGTH;
	memcpy(ctx->state, H0_224, sizeof(H0_224));
}

void sha256_init (sha256_ctx_t *ctx)
{
	memset (ctx,0,sizeof(*ctx));
	ctx->init     = sha256_init;
	ctx->update   = sha256_update;
	ctx->final    = sha256_final;
	ctx->total    = 0UL;
	ctx->buf_len  = 0;
	ctx->buf_size = SHA256_BUF_SIZE;
	ctx->md_len   = SHA256_DIGEST_LENGTH;
	memcpy(ctx->state, H0_256, sizeof(H0_256));
}

static void sha256_update(sha256_ctx_t *ctx, uint8_t *data, size_t len)
{
	size_t i;

	if (len + ctx->buf_len > SHA256_BUF_SIZE - 1) {
		i = SHA256_BUF_SIZE - ctx->buf_len;
		memcpy(&ctx->buffer[ctx->buf_len], data, i);
		sha256_run(ctx->state, ctx->buffer);
		for (; i+SHA256_BUF_SIZE-1<len; i+=SHA256_BUF_SIZE) {
			sha256_run(ctx->state, &data[i]);
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

static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[])
{
	int i;
	uint8_t byte;
	uint64_t qw;

	qw = ctx->total * 8;
	byte = 0x80;
	sha256_update(ctx, &byte, 1);

	byte = 0x00;
	while (ctx->buf_len != SHA256_BUF_SIZE - sizeof(qw))
		sha256_update(ctx, &byte, 1);

	qw = swap64(qw);
	sha256_update(ctx, (uint8_t *)&qw, sizeof(qw)); /* trigger sha256_run() */

	for (i=0; i<ARRAY_SIZE(ctx->state); i++)
		ctx->state[i] = swap32(ctx->state[i]);
	memcpy(digest, ctx->state, ctx->md_len/8);

	ctx->init(ctx);
}

