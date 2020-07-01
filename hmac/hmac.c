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
#include "hmac.h"

static void hmac_update(hmac_ctx_t *ctx, uint8_t *data, size_t len);
static int  hmac_final(hmac_ctx_t *ctx, uint8_t dgst[]);

int  hmac_init(hmac_ctx_t *ctx, uint8_t *key, int key_len, int hash_id)
{
	size_t i;
	uint8_t k[MAX_HASH_KEYLEN];
	sha_ctx_t *sha = &ctx->sha;

	memset(k, 0, sizeof(k));
	memset(ctx, 0, sizeof(*ctx));

	ctx->init   = hmac_init;
	ctx->update = hmac_update;
	ctx->final  = hmac_final;

	ctx->hash_id = hash_id;
	if (hash_init(hash_id, sha)) return -1;

	if (key_len > sha->buf_size) {
		sha->update(sha, key, key_len);
		sha->final(sha, k);
	}
	else {
		memcpy(k, key, key_len);
	}

	for (i=0; i<sha->buf_size; i++) {
		ctx->key1[i] = k[i] ^ 0x36;
		ctx->key2[i] = k[i] ^ 0x5c;
	}
	sha->update(sha, ctx->key1, sha->buf_size);
	return sha->md_len/8;
}

static void hmac_update(hmac_ctx_t *ctx, uint8_t *data, size_t len)
{
	sha_ctx_t *sha = (sha_ctx_t *)&ctx->sha;
	sha->update(sha, data, len);
}

static int  hmac_final(hmac_ctx_t *ctx, uint8_t dgst[])
{
	uint8_t hash[MAX_HASH_KEYLEN];
	sha_ctx_t *sha = (sha_ctx_t *)&ctx->sha;

	memset(hash, 0, sizeof(hash));
	sha->final(sha, hash);

	sha->update(sha, ctx->key2, sha->buf_size);
	sha->update(sha, hash, sha->md_len/8);
	sha->final(sha, dgst);

	return sha->md_len / 8;
}

