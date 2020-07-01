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
#include "random.h"
#include "rsaes-oaep.h"


       int mgf1(sha_ctx_t *ctx, int cnt0, uint8_t *seed, int seedlen, uint8_t *mask, int msklen);
static int rsaes_oaep_encodepad(rsaes_oaep_ctx_t *ctx, size_t msglen, uint8_t *msg, char *label, uint8_t *em);
static int rsaes_oaep_decodepad(rsaes_oaep_ctx_t *ctx, int emlen, uint8_t *em, char *label, int *outlen, uint8_t *out);


int rsaes_oaep_init(rsaes_oaep_ctx_t *ctx, int rsa_nbits, enum hash_id hash_id)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->init      = rsaes_oaep_init;
	ctx->encodepad = rsaes_oaep_encodepad;
	ctx->decodepad = rsaes_oaep_decodepad;

	ctx->k = (rsa_nbits + 7) / 8;

	ctx->hash_id = hash_id;
	if (hash_init(hash_id, &ctx->hash)) return -1;

	return 0;
}

/* array em must be long enough to hold 0x00, maskedSeed, maskedDB, it should be at least ctx->k bytes long */
static int rsaes_oaep_encodepad(rsaes_oaep_ctx_t *ctx, size_t msglen, uint8_t *msg, char *label, uint8_t *em)
{
	int i;
	uint32_t hlen;
	uint8_t seed[SHA_DIGEST_LENGTH/8];
	uint8_t *lhash, *maskedDB, *pM, *maskedSeed;

	maskedSeed = lhash = em + 1;
	/* 1. Length checking */
	if ((ctx->hash_id == eHASH_SHA1) && label && (strlen(label) > (2UL<<61 - 1))) return -1;

	if (msglen > ctx->k - 2 * ctx->hash.md_len / 8) return -2;

	/* 2. EME-OAEP encoding */
	/* 2.a create lHash from label */
	ctx->hash.init(&ctx->hash);
	hlen = ctx->hash.md_len / 8;		
	if (label)
		ctx->hash.update(&ctx->hash, label, strlen(label));
	else
		ctx->hash.update(&ctx->hash, "", 0);
	ctx->hash.final(&ctx->hash, lhash);

	/* 2.b */
	/* 2.c */
	/* 2.d generate random seed */
	if (get_random(hlen*8, seed) != hlen*8) return -3;
#ifdef PKCS1_OAEP_TESTVECT
	memcpy(seed, "\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2\xf0\x6c\xb5\x8f", 20);
#endif
	/* 2.e get dbMask = MGF(seed, k-hLen - 1) */
	maskedDB = em + 1 + hlen;
	if (mgf1(&ctx->hash, 0, seed, hlen, maskedDB, ctx->k - 1 - hlen)) return -4;
	/* 2.c Concatenate to get DB = lHash || PS || 0x01 || M, 2.f maskedDB = DB ^ dbMask */
	for (i=0; i<hlen; i++) maskedDB[i] ^= lhash[i];
	em[ctx->k - msglen - 1] ^= 0x01;
	pM = &em[ctx->k - msglen];
	for (i=0; i<msglen; i++) pM[i] ^= msg[i];
	/* 2.g seedMask = MGF(maskedDB, hLen) */
	if (mgf1(&ctx->hash, 0, maskedDB, ctx->k - 1 - hlen, maskedSeed, hlen)) return -5;
	/* 2.h maskedSeed = seed XOR seedMask*/
	for (i=0; i<hlen; i++) maskedSeed[i] ^= seed[i];
	/* 2.i Concatenate to EM = 0x00 || maskedSeed || maskedDB */
	em[0] = 0;
	/* 3 RSA encryption */
	//rsa_enc(em, &ctx->pubkey, em);
	return 0;
}

static int rsaes_oaep_decodepad(rsaes_oaep_ctx_t *ctx, int emlen, uint8_t *em, char *label, int *outlen, uint8_t *out)
{
	int i, j, k;
	uint32_t hlen, olen;
	uint8_t *pmsg, *dbMask_hlen;
	uint8_t seed[SHA_DIGEST_LENGTH/8];
	uint8_t lhash[SHA_DIGEST_LENGTH/8];

	/* 1. Length checking */
	if ((ctx->hash_id == eHASH_SHA1) && label && (strlen(label) > (2UL<<61 - 1))) return -1;
	if (emlen != ctx->k) return -2;
	if (ctx->k < 2 * ctx->hash.md_len / 8 + 2) return -3;
	/* 3. EME-OAEP decoding */
	/* 3.a lHash = HASH(L) */
	ctx->hash.init(&ctx->hash);
	hlen = ctx->hash.md_len / 8;
	if (label)
		ctx->hash.update(&ctx->hash, label, strlen(label));
	else
		ctx->hash.update(&ctx->hash, "", 0);
	ctx->hash.final(&ctx->hash, lhash);
	/* 3.b 3.c seedMask = MGF(maskedDB, hlen) */
	if (mgf1(&ctx->hash, 0, &em[1 + hlen], ctx->k - 1 - hlen, seed, hlen)) return -4;
	/* 3.d seed = maskedSeed XOR seedMask */
	for (i=0; i<hlen; i++) seed[i] ^= em[1 + i];
	/* 3.e dbMask = MGF(seed, k-hLen-1) */
	/* 3.f DB = maskedDB XOR dbMask */
	dbMask_hlen = &em[1];
	for (olen=1+hlen,i=0; olen<ctx->k; i++, olen+=hlen) {
		if (mgf1(&ctx->hash, i, seed, hlen, dbMask_hlen, hlen)) return -4;
		k = ctx->k - olen;
		if (k > hlen) k = hlen;
		for (j=0; j<k; j++) em[olen+j] ^= dbMask_hlen[j];
	}
	/* 3.g */
	pmsg = memchr(&em[1+2*hlen], 0x01, ctx->k-1-2*hlen);
	if (em[0] || memcmp(lhash, &em[1+hlen], hlen) || !pmsg) return -5;
	*outlen = em + ctx->k - ++pmsg;
	memcpy(out, pmsg, *outlen);
	return 0;
}

/* B.2.1 of PKCS#1 2.2 */
int mgf1(sha_ctx_t *ctx, int cnt0, uint8_t *seed, int seedlen, uint8_t *mask, int msklen)
{
	int i, outlen;
	int hlen;
	uint32_t cnt;
	uint8_t md[SHA_DIGEST_LENGTH/8];

	hlen = ctx->md_len / 8;
	/* 1 */
	/* because msklen is int type, so it won't > 2^32 * hlen */
	/* 2, 3, 4 */
	for (outlen=0, i=cnt0; outlen<msklen; i++) {
		cnt = swap32(i);
		ctx->init(ctx);
		ctx->update(ctx, seed, seedlen);
		ctx->update(ctx, (uint8_t *)&cnt, 4);
		if (outlen + hlen <= msklen) {
			ctx->final(ctx, mask + outlen);
			outlen += hlen;
		}
		else {
			ctx->final(ctx, md);
			memcpy(mask + outlen, md, msklen - outlen);
			outlen = msklen;
		}
	}
	return 0;
}

