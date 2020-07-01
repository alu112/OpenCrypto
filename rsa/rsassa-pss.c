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
#include "rsassa-pss.h"


#ifdef RSA_NIST_TEST
uint8_t g_salt[512];
#endif

extern int mgf1(sha_ctx_t *ctx, int cnt0, uint8_t *seed, int seedlen, uint8_t *mask, int msklen);
static int rsassa_pss_encodepad(rsassa_pss_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, uint8_t *em);
static int rsassa_pss_decodepad(rsassa_pss_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, int emlen, uint8_t *em);


int rsassa_pss_init(rsassa_pss_ctx_t *ctx, int rsa_nbits, enum hash_id hash_id)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->init      = rsassa_pss_init;
	ctx->encodepad = rsassa_pss_encodepad;
	ctx->decodepad = rsassa_pss_decodepad;

	ctx->k = (rsa_nbits + 7)/ 8;
	ctx->nbits = rsa_nbits;
	/* 
	 * openssl allows MSB of rsa->n to be zero,
	 * we don't allow this weak key.
	 */
	if (((rsa_nbits+31)/32)*32 != ctx->k*8) return -2;

	ctx->hash_id = hash_id;
	if (hash_init(hash_id, &ctx->hash)) return -1;

	return 0;
}

/* array em must be long enough to hold maskedDB, H, 0xbc, it should be at least ctx->k bytes long */
static int rsassa_pss_encodepad(rsassa_pss_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, uint8_t *em)
{
	int i, j, k, slen;
	uint32_t hlen, olen;
	uint8_t zeros[8] = { 0,0,0,0, 0,0,0,0};
	uint8_t mhash[SHA_DIGEST_LENGTH/8];
	uint8_t *salt, *H;

	/* 1. Length checking */
	if ((ctx->hash_id == eHASH_SHA1) && (msglen > (2UL<<61 - 1))) return -1;
	/* 2. mHash = Hash(M) */
	ctx->hash.init(&ctx->hash);
	hlen = ctx->hash.md_len / 8;		
	ctx->hash.update(&ctx->hash, msg, msglen);
	ctx->hash.final(&ctx->hash, mhash);
	/* 3 if emLen < hLen + sLen +2 output "message too long" and stop */
	slen = salt_len;
	if (salt_len == RSA_PSS_SALTLEN_DIGEST) slen = hlen;
	else if (salt_len < 0) return -3;
	if (ctx->k < hlen + slen + 2) return -2;
	/* 4 Generate a random octet string salt of length sLen;
	 * if sLen = 0, then salt is the empty string
	 */
	salt = &em[ctx->k - 1 - hlen - slen];
	if (get_random(slen*8, salt) != slen*8) return -3;
#ifdef RSA_NIST_TEST
	memcpy(salt, g_salt, slen);
#endif
	/* 5. Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	 * 6. H = Hash(M')
	 */
	H = &em[ctx->k - 1 - hlen];
	ctx->hash.init(&ctx->hash);
	ctx->hash.update(&ctx->hash, zeros, sizeof(zeros));
	ctx->hash.update(&ctx->hash, mhash, hlen);
	ctx->hash.update(&ctx->hash, salt, slen);
	ctx->hash.final(&ctx->hash, H);
	/* 7. Generate an octet string PS consisting of emLen – sLen – hLen – 2 zero octets.
	 *    The length of PS may be 0.
	 */
	memset(em, 0, ctx->k - slen - hlen - 2);
	/* 8. Let DB = PS || 0x01 || salt; DB is an octet string of length emLen – hLen – 1 */
	em[ctx->k - slen - hlen - 2] = 0x01;
	/* 9. Let dbMask = MGF (H, emLen – hLen – 1)
	 * 10. Let maskedDB = DB XOR dbMask
	 */
	for (olen=i=0; olen<ctx->k-hlen-1; i++, olen+=hlen) {
		/* use mhash[] to save mgf1 output */
		if (mgf1(&ctx->hash, i, H, hlen, mhash, hlen)) return -4;
		k = ctx->k-hlen-1 - olen;
		if (k > hlen) k = hlen;
		for (j=0; j<k; j++) em[olen+j] ^= mhash[j];
	}
	/* 11. Set the leftmost 8emLen – emBits bits of the leftmost octet in maskedDB to zero. */
	em[0] &= 0xFF>>(8-ctx->nbits%8);
	/* 12. Let EM = maskedDB || H || 0xbc */
	em[ctx->k - 1] = 0xbc;
	/* 3 RSA encryption */
	//rsa_enc(em, &ctx->pubkey, em);
	return 0;
}

static int rsassa_pss_decodepad(rsassa_pss_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, int emlen, uint8_t *em)
{
	int i, j, k, slen;
	uint32_t hlen, olen;
	uint8_t *H, *salt;
	uint8_t zeros[8] = { 0,0,0,0, 0,0,0,0};
	uint8_t mhash[SHA_DIGEST_LENGTH/8];
	uint8_t dbMask[SHA_DIGEST_LENGTH/8];

	/* 1. Length checking */
	if ((ctx->hash_id == eHASH_SHA1) && (msglen > (2UL<<61 - 1))) return -1;
	/* 2. mHash = Hash(M) */
	ctx->hash.init(&ctx->hash);
	hlen = ctx->hash.md_len / 8;		
	ctx->hash.update(&ctx->hash, msg, msglen);
	ctx->hash.final(&ctx->hash, mhash);
	/* 3 if emLen < hLen + sLen +2 output "inconsistent" and stop */
	slen = salt_len;
	if (salt_len == RSA_PSS_SALTLEN_DIGEST) slen = hlen;
	else if (slen < 0) return -3;
	if (ctx->k < hlen + slen + 2) return -2;
	/* 4. If the rightmost octet of EM does not have hexadecimal value 0xbc, 
	 *    output "inconsistent" and stop
	 */
	if (em[ctx->k - 1] != 0xbc) return -3;
	/* 5. Let maskedDB be the leftmost emLen – hLen – 1 octets of EM, and let H be the next hLen octets. */
	H = &em[ctx->k - 1 - hlen];
	/* 6. If the leftmost 8emLen – emBits bits of the leftmost octet in maskedDB are not all
	 *    equal to zero, output "inconsistent" and stop.
	 */
	if (em[0] & (0xFF<<(ctx->nbits%8))) return -4;
	/* 7. Let dbMask = MGF (H, emLen – hLen – 1) */
	/* 8. Let DB = maskedDB XOR dbMask */	
	for (olen=i=0; olen<ctx->k-hlen-1; i++, olen+=hlen) {
		if (mgf1(&ctx->hash, i, H, hlen, dbMask, hlen)) return -4;
		k = ctx->k-hlen-1 - olen;
		if (k > hlen) k = hlen;
		for (j=0; j<k; j++) em[olen+j] ^= dbMask[j];
	}
	/* 9. Set the leftmost 8emLen – emBits bits of the leftmost octet in DB to zero */
	em[0] &= 0xFF>>(8-ctx->nbits%8);
	/* 10. If the emLen – hLen – sLen – 2 leftmost octets of DB are not zero or if the octet at
	 *     position emLen – hLen – sLen – 1 (the leftmost position is “position 1”) does not
	 *     have hexadecimal value 0x01, output “inconsistent” and stop
	 */
	for (i=0; i<ctx->k-2-hlen-slen; i++)
		if (em[i]) return -5;
	if (em[i] != 0x01) return -6;
	/* 11. Let salt be the last sLen octets of DB */
	salt = &em[++i];
	/* 12. Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
	/* 13. Let Let H' = Hash (M'), an octet string of length hLen */
	ctx->hash.init(&ctx->hash);
	ctx->hash.update(&ctx->hash, zeros, sizeof(zeros));
	ctx->hash.update(&ctx->hash, mhash, hlen);
	ctx->hash.update(&ctx->hash, salt, slen);
	ctx->hash.final(&ctx->hash, mhash);
	/* 14. If H = H', output "consistent" Otherwise, output "inconsistent" */
	return memcmp(H, mhash, hlen);
}

