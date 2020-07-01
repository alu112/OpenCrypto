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

#ifndef __CHIPHER_MODE__
#define __CHIPHER_MODE__

#include <stdint.h>
#include "paddings.h"

#define CIPHER_CTX_MAX_BLK_LEN 16

typedef struct blk_ctx blk_ctx_t;

/* common struct of aes and des */
struct blk_ctx {
        int     (*init)(blk_ctx_t *ctx, uint8_t *key);
        void (*encrypt)(blk_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
        void (*decrypt)(blk_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
        int  keylen, blklen; /* all lengths are in bits */
};

typedef struct cipher_ctx cipher_ctx_t;

/*
 * the encrypt and decrypt are in-place operation, so the input
 * buffer block has to be long enough for paddings.
 * if don't use padding, then the block length should be multiple
 * of blk->blklen
 */
struct cipher_ctx {
	void      (*init)(cipher_ctx_t* ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv);
	size_t (*encrypt)(cipher_ctx_t *ctx, uint8_t *block, size_t len);
	size_t (*decrypt)(cipher_ctx_t *ctx, uint8_t *block, size_t len);
	pad_ctx_t *pad;
	blk_ctx_t *cipher; /* block cipher context: DES, AES */
	int      ivlen;    /* bytes */
	uint8_t  iv[CIPHER_CTX_MAX_BLK_LEN];
};

void cbc_init(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv);
void ecb_init(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *iv);
/*
 * nounce in ctr mode contains 96-bit iv and 32-bit counter value 
 * first 12 bytes are iv
 * last   4 bytes are counter
 */
void ctr_init(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *nounce);
void ofb_init(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *nounce);
void cfb_init(cipher_ctx_t *ctx, blk_ctx_t *blk_ctx, pad_ctx_t *pad, uint8_t *nounce);

#endif /* __CHIPHER_MODE__ */

