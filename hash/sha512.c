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
#include "sha512.h"

REGISTER_HASH_ALGO(eHASH_SHA512_224, sha512_224_init);
REGISTER_HASH_ALGO(eHASH_SHA512_256, sha512_256_init);
REGISTER_HASH_ALGO(eHASH_SHA384,     sha384_init);
REGISTER_HASH_ALGO(eHASH_SHA512,     sha512_init);

static void sha512_run(uint64_t state[8], uint8_t data[SHA512_BUF_SIZE]);
static void sha512_update(sha512_ctx_t *ctx, uint8_t *data, size_t len);
static void sha512_final(sha512_ctx_t *ctx, uint8_t digest[]);

static const uint64_t K[80] = {
	0x428a2f98d728ae22UL,0x7137449123ef65cdUL,
	0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,
	0x3956c25bf348b538UL,0x59f111f1b605d019UL,
	0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,
	0xd807aa98a3030242UL,0x12835b0145706fbeUL,
	0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,
	0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,
	0x9bdc06a725c71235UL,0xc19bf174cf692694UL,
	0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,
	0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,
	0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,
	0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,
	0x983e5152ee66dfabUL,0xa831c66d2db43210UL,
	0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,
	0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,
	0x06ca6351e003826fUL,0x142929670a0e6e70UL,
	0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,
	0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,
	0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,
	0x81c2c92e47edaee6UL,0x92722c851482353bUL,
	0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,
	0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,
	0xd192e819d6ef5218UL,0xd69906245565a910UL,
	0xf40e35855771202aUL,0x106aa07032bbd1b8UL,
	0x19a4c116b8d2d0c8UL,0x1e376c085141ab53UL,
	0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,
	0x391c0cb3c5c95a63UL,0x4ed8aa4ae3418acbUL,
	0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,
	0x748f82ee5defb2fcUL,0x78a5636f43172f60UL,
	0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,
	0x90befffa23631e28UL,0xa4506cebde82bde9UL,
	0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,
	0xca273eceea26619cUL,0xd186b8c721c0c207UL,
	0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,
	0x06f067aa72176fbaUL,0x0a637dc5a2c898a6UL,
	0x113f9804bef90daeUL,0x1b710b35131c471bUL,
	0x28db77f523047d84UL,0x32caab7b40c72493UL,
	0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,
	0x4cc5d4becb3e42b6UL,0x597f299cfc657e2aUL,
	0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL 
};
static const uint64_t H0_512_224[] = {
	0x8C3D37C819544DA2UL,0x73E1996689DCD4D6UL,
	0x1DFAB7AE32FF9C82UL,0x679DD514582F9FCFUL,
	0x0F6D2B697BD44DA8UL,0x77E36F7304C48942UL,
	0x3F9D85A86A1D36C8UL,0x1112E6AD91D692A1UL
};

static const uint64_t H0_512_256[] = {
	0x22312194FC2BF72CUL,0x9F555FA3C84C64C2UL,
	0x2393B86B6F53B151UL,0x963877195940EABDUL,
	0x96283EE2A88EFFE3UL,0xBE5E1E2553863992UL,
	0x2B0199FC2C85B8AAUL,0x0EB72DDC81C52CA2UL
};

static const uint64_t H0_384[] = {
	0xcbbb9d5dc1059ed8UL,0x629a292a367cd507UL,
	0x9159015a3070dd17UL,0x152fecd8f70e5939UL,
	0x67332667ffc00b31UL,0x8eb44a8768581511UL,
	0xdb0c2e0d64f98fa7UL,0x47b5481dbefa4fa4UL
};

static const uint64_t H0_512[] = {
	0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,
	0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL,
	0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,
	0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL
};

#define Ch(x,y,z)     (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0(x)     (ROTR64((x),28) ^ ROTR64((x),34) ^ ROTR64((x),39))
#define Sigma1(x)     (ROTR64((x),14) ^ ROTR64((x),18) ^ ROTR64((x),41))
#define sigma0(x)     (ROTR64((x), 1) ^ ROTR64((x), 8) ^ SHR((x), 7))
#define sigma1(x)     (ROTR64((x),19) ^ ROTR64((x),61) ^ SHR((x), 6))


#define W(t) (x[t&15] = sigma1(x[(t-2)&15]) + x[(t-7)&15] + sigma0(x[(t-15)&15]) + x[t&15])


#define R(A,B,C,D,E,F,G,H,K,W,T1,T2)                      \
	do {                                              \
		T1 = H + Sigma1(E) + Ch(E, F, G) + K + W; \
		T2 = Sigma0(A) + Maj(A, B, C);            \
		D += T1;                                  \
		H  = T1 + T2;                             \
	} while(0)


static void sha512_run(uint64_t state[8], uint8_t data[SHA512_BUF_SIZE])
{
	uint64_t i, a, b, c, d, e, f, g, h, x[16], t1, t2;

	memcpy(x, data, sizeof(x)); /* avoid alignment issue */
	for (i=0; i<16; i++)
		x[i] = swap64(x[i]);

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
	R( a, b, c, d, e, f, g, h, K[64], W(64), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[65], W(65), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[66], W(66), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[67], W(67), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[68], W(68), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[69], W(69), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[70], W(70), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[71], W(71), t1, t2 );
	R( a, b, c, d, e, f, g, h, K[72], W(72), t1, t2 );
	R( h, a, b, c, d, e, f, g, K[73], W(73), t1, t2 );
	R( g, h, a, b, c, d, e, f, K[74], W(74), t1, t2 );
	R( f, g, h, a, b, c, d, e, K[75], W(75), t1, t2 );
	R( e, f, g, h, a, b, c, d, K[76], W(76), t1, t2 );
	R( d, e, f, g, h, a, b, c, K[77], W(77), t1, t2 );
	R( c, d, e, f, g, h, a, b, K[78], W(78), t1, t2 );
	R( b, c, d, e, f, g, h, a, K[79], W(79), t1, t2 );

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

void sha512_224_init (sha512_ctx_t *ctx)
{
        memset (ctx,0,sizeof(*ctx));
        ctx->init     = sha512_224_init;
        ctx->update   = sha512_update;
        ctx->final    = sha512_final;
        ctx->total    = 0UL;
        ctx->buf_len  = 0;
        ctx->buf_size = SHA512_BUF_SIZE;
        ctx->md_len   = SHA224_DIGEST_LENGTH;
        memcpy(ctx->state, H0_512_224, sizeof(H0_512_224));
}

void sha512_256_init (sha512_ctx_t *ctx)
{
        memset (ctx,0,sizeof(*ctx));
        ctx->init     = sha512_256_init;
        ctx->update   = sha512_update;
        ctx->final    = sha512_final;
        ctx->total    = 0UL;
        ctx->buf_len  = 0;
        ctx->buf_size = SHA512_BUF_SIZE;
        ctx->md_len   = SHA256_DIGEST_LENGTH;
        memcpy(ctx->state, H0_512_256, sizeof(H0_512_256));
}

void sha384_init (sha512_ctx_t *ctx)
{
	memset (ctx,0,sizeof(*ctx));
	ctx->init     = sha384_init;
	ctx->update   = sha512_update;
	ctx->final    = sha512_final;
	ctx->total    = 0UL;
	ctx->buf_len  = 0;
	ctx->buf_size = SHA512_BUF_SIZE;
	ctx->md_len   = SHA384_DIGEST_LENGTH;
	memcpy(ctx->state, H0_384, sizeof(H0_384));
}

void sha512_init (sha512_ctx_t *ctx)
{
	memset (ctx,0,sizeof(*ctx));
	ctx->init     = sha512_init;
	ctx->update   = sha512_update;
	ctx->final    = sha512_final;
	ctx->total    = 0UL;
	ctx->buf_len  = 0;
	ctx->buf_size = SHA512_BUF_SIZE;
	ctx->md_len   = SHA512_DIGEST_LENGTH;
	memcpy(ctx->state, H0_512, sizeof(H0_512));
}

static void sha512_update(sha512_ctx_t *ctx, uint8_t *data, size_t len)
{
	size_t i;

	if (len + ctx->buf_len > SHA512_BUF_SIZE - 1) {
		i = SHA512_BUF_SIZE - ctx->buf_len;
		memcpy(&ctx->buffer[ctx->buf_len], data, i);
		sha512_run(ctx->state, ctx->buffer);
		for (; i+SHA512_BUF_SIZE-1<len; i+=SHA512_BUF_SIZE) {
			sha512_run(ctx->state, &data[i]);
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

static void sha512_final(sha512_ctx_t *ctx, uint8_t digest[])
{
	int i;
	uint8_t byte;
	uint128_t xw; /* 16 bytes */

	xw = ctx->total * 8;
	byte = 0x80;
	sha512_update(ctx, &byte, 1);

	byte = 0x00;
	while (ctx->buf_len != SHA512_BUF_SIZE - sizeof(xw))
		sha512_update(ctx, &byte, 1);

	xw = swap128(xw);
	sha512_update(ctx, (uint8_t *)&xw, sizeof(xw)); /* trigger sha512_run() */

	for (i=0; i<ARRAY_SIZE(ctx->state); i++)
		ctx->state[i] = swap64(ctx->state[i]);
	memcpy(digest, ctx->state, ctx->md_len/8);
	
	ctx->init(ctx);
}

#if 0

#include <assert.h>
#include <stdio.h>

/*
 * sha512/t IV calculation
 * 
 * Section 5.3.6 of NIST.FIPS.180-4.pdf
 *
 * SHA-512/224 (t = 224) and SHA-512/256 (t = 256) are approved hash algorithms.
 * Other SHA512/t hash algorithms with different t values may be specified in 
 * [SP 800-107] in the future as the need arises
 */
void sha512t_iv(int t)
{
	int i;
	sha512_ctx_t ctx;
	uint64_t H0t[8], H0[8];
	uint8_t  msg[16];

	assert(t<512 && t!=384);

	for (i=0; i<8; i++) {
		H0t[i] = H0_512[i] ^ 0xa5a5a5a5a5a5a5a5UL;
	}
	sha512_init(&ctx);
	memcpy(ctx.state, H0t, sizeof(H0t));
	sprintf(msg, "SHA-512/%d", t);
	sha512_update(&ctx, msg, strlen(msg));
	sha512_final(&ctx, (uint8_t*)H0);
	printf("IV of %s is:\n", msg);
	for (i=0; i<8; i+=2) {
		H0[i]   = swap64(H0[i]);
		H0[i+1] = swap64(H0[i+1]);
		printf("%016lx %016lx\n", H0[i], H0[i+1]);
	}
	printf("\n");
}
#endif

