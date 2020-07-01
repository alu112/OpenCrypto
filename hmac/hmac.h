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

#ifndef __HMAC_H__
#define __HMAC_H__

#include <stdint.h>
#include "sha-common.h"


typedef struct hmac_ctx hmac_ctx_t;

struct hmac_ctx {
	/* return the bytes of message digest */
	int  (*init)(hmac_ctx_t *ctx, uint8_t *key, int key_len, int hash_id);
	void (*update)(hmac_ctx_t *ctx, uint8_t *data, size_t len);
	/* return the bytes of message digest */
	int  (*final)(hmac_ctx_t *ctx, uint8_t dgst[]);

#define MAX_HASH_KEYLEN 256
	uint8_t key1[MAX_HASH_KEYLEN]; /* key xor ipad */
	uint8_t key2[MAX_HASH_KEYLEN]; /* key xor opad */
	enum hash_id hash_id;
	sha_ctx_t sha;
};

int  hmac_init(hmac_ctx_t *ctx, uint8_t *key, int key_len, int hash_id);

#endif /* __HMAC_H__ */

