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

#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include <stddef.h>

typedef struct aes_ctx aes_ctx_t;

struct aes_ctx {
	int     (*init)(aes_ctx_t *ctx, uint8_t *key, int keylen);
	void (*encrypt)(aes_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
	void (*decrypt)(aes_ctx_t *ctx, uint8_t *blocks, size_t nblocks);
	int  keylen, blklen; /* all lengths in bits */
	uint8_t key[256/8];
	uint8_t roundkey[60*16]; /*big enough for aes-128,192,256 */
};

int  aes_init(aes_ctx_t *ctx, uint8_t *key, int keylen);

#endif /* __AES_H__ */

