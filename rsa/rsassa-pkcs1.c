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
#include "rsassa-pkcs1.h"


static int rsassa_pkcs1_encodepad(rsassa_pkcs1_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, uint8_t *em);
static int rsassa_pkcs1_decodepad(rsassa_pkcs1_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, int emlen, uint8_t *em);

static const struct id2oid {
	enum hash_id id;
	int     oid_len;
	uint8_t oid[24];
} id2oid_array[] = {
	{ eHASH_SHA1,       15, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14" },
	{ eHASH_SHA224,     19, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c" },
	{ eHASH_SHA256,     19, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20" },
	{ eHASH_SHA384,     19, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30" },
	{ eHASH_SHA512,     19, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40" },
	{ eHASH_SHA512_224, 19, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x05\x00\x04\x1c" },
	{ eHASH_SHA512_256, 19, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00\x04\x20" },
	{ eHASH_SHA3_224,    0, "" },
	{ eHASH_SHA3_256,    0, "" },
	{ eHASH_SHA3_384,    0, "" },
	{ eHASH_SHA3_512,    0, "" }
};

static const struct id2oid *id2oid(enum hash_id id)
{
	int i;

	for (i=0; i<ARRAY_SIZE(id2oid_array); i++)
		if (id2oid_array[i].id == id)
			return &id2oid_array[i];
	return NULL;
}

int rsassa_pkcs1_init(rsassa_pkcs1_ctx_t *ctx, int rsa_nbits, enum hash_id hash_id)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->init      = rsassa_pkcs1_init;
	ctx->encodepad = rsassa_pkcs1_encodepad;
	ctx->decodepad = rsassa_pkcs1_decodepad;

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
static int rsassa_pkcs1_encodepad(rsassa_pkcs1_ctx_t *ctx, size_t msglen, uint8_t *msg, int not_used, uint8_t *em)
{
	uint32_t hlen;
	uint8_t *pT;
	const struct id2oid *poid = id2oid(ctx->hash_id);

	/* 1. Length checking */
	if ((ctx->hash_id == eHASH_SHA1) && (msglen > (2UL<<61 - 1))) return -1;
	/* 2. mHash = Hash(M) */
	ctx->hash.init(&ctx->hash);
	hlen = ctx->hash.md_len / 8;		
	/* 3 if emLen < tLen + 11 output "message too short" and stop */
	if (ctx->k < hlen + poid->oid_len + 11) return -2;
	/* 4. Generate an octet string PS consisting of emLen – tLen – 3 octets with
	 *    hexadecimal value 0xff. The length of PS will be at least 8 octets
	 * 5. Concatenate PS, the DER encoding T, and other padding to form the encoded
	 *    message EM as EM = 0x00 || 0x01 || PS || 0x00 || T
	 */
	memset(em, 0xFF, ctx->k);
	em[0] = 0x00;
	em[1] = 0x01;
	pT = &em[ctx->k - hlen - poid->oid_len - 1];
	*pT++ = 0x00;
	memcpy(pT, poid->oid, poid->oid_len);
	pT += poid->oid_len;
	ctx->hash.update(&ctx->hash, msg, msglen);
	ctx->hash.final(&ctx->hash, pT);

	/* 3 RSA encryption */
	//rsa_enc(em, &ctx->pubkey, em);
	return 0;
}

static int rsassa_pkcs1_decodepad(rsassa_pkcs1_ctx_t *ctx, size_t msglen, uint8_t *msg, int not_used, int emlen, uint8_t *em)
{
	uint8_t em1[8192]; /* an arbitrary bigger number */

	/* 1. Length checking */
	if ((ctx->hash_id == eHASH_SHA1) && (msglen > (2UL<<61 - 1))) return -1;
	if (emlen != ctx->k) return -2;

	if (ctx->k > sizeof(em1)) return -3; /* signature too big to put in em1[] */

	ctx->encodepad(ctx, msglen, msg, not_used, em1);

	return memcmp(em, em1, emlen);
}

