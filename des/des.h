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

#ifndef __DES_H__
#define __DES_H__

#include <stdint.h>
#include <stddef.h>

#define DES_ENCRYPT 0
#define DES_DECRYPT 1

typedef struct des_ctx des_ctx_t;

struct des_ctx {
	int     (*init)(des_ctx_t *ctx, uint8_t *key);
	void (*encrypt)(des_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
	void (*decrypt)(des_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
	int  keylen, blklen; /* all length in bits */
	uint8_t key[8];
	uint64_t keyset48[16];
};

typedef struct tdes_ctx tdes_ctx_t;

struct tdes_ctx {
	int     (*init)(tdes_ctx_t *ctx, uint8_t *keys, int keylen);
	void (*encrypt)(tdes_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
	void (*decrypt)(tdes_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
	int  keylen, blklen;
	uint8_t key[3][8];
	uint64_t keyset48[3][16];
};

int  des_init(des_ctx_t *ctx, uint8_t *key);
int tdes_init(tdes_ctx_t *ctx, uint8_t *keys, int keylen);

#endif /* __DES_H__ */

