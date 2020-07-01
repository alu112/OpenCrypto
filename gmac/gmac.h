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

#ifndef __GMAC_H__
#define __GMAC_H__

#include <stdint.h>
#include "cipher-mode.h"
#include "aes.h"

typedef struct gmac_ctx gmac_ctx_t;

struct gmac_ctx {
	/* return the bytes of message digest */
	int  (*init)(gmac_ctx_t *ctx, uint8_t *iv, size_t iv_len, uint8_t *aad, size_t aad_len, int tag_len, blk_ctx_t *cipher);
	void (*encrypt)(gmac_ctx_t *ctx, uint8_t x[], size_t xn, uint8_t tag[]);
	int  (*decrypt)(gmac_ctx_t *ctx, uint8_t x[], size_t xn, uint8_t tag[]);
	blk_ctx_t *cipher;
	int    tag_len;
	int    iv_len;
	size_t aad_len;
	uint8_t   j0[16];
	uint128_t aad; /* authentication data */
	uint128_t h; /* hash_subkey */
};

int  gmac_init(gmac_ctx_t *ctx, uint8_t *iv, size_t iv_len, uint8_t *aad, size_t aad_len, int tag_len, blk_ctx_t *cipher);

#endif /* __GMAC_H__ */

