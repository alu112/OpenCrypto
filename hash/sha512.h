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

#ifndef __SHA512_H__
#define __SHA512_H__

#include <string.h>
#include "sha-common.h"

#define SHA512_BUF_SIZE       128


typedef struct sha512_ctx sha512_ctx_t;

struct sha512_ctx {
	void (*init)(sha512_ctx_t *ctx);
	void (*update)(sha512_ctx_t *ctx, uint8_t *data, size_t len);
	void (*final)(sha512_ctx_t *ctx, uint8_t digest[]);

	uint32_t md_len;     /* message digest bit length */
	uint32_t buf_len;    /* bytes in buffer */
	uint32_t buf_size;   /* the size of buffer in bytes */
	uint128_t total;     /* total bytes have been processed */
	uint64_t state[SHA512_DIGEST_LENGTH / 64];
	uint8_t  buffer[SHA512_BUF_SIZE];
};

void sha512_224_init(sha512_ctx_t *ctx);
void sha512_256_init(sha512_ctx_t *ctx);
void sha384_init(sha512_ctx_t *ctx);
void sha512_init(sha512_ctx_t *ctx);

#endif /* __SHA512_H__ */

