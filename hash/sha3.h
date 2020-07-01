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

#ifndef __SHA3_H__
#define __SHA3_H__

#include <string.h>
#include <sha-common.h>

/*
 * Note: 
 * this implementation only support message length
 * is multiple of 8 bits.
 */
typedef struct sha3_ctx sha3_ctx_t;

struct sha3_ctx {
	void (*init)(sha3_ctx_t *ctx);
	void (*update)(sha3_ctx_t *ctx, uint8_t *data, size_t len);
	void (*final)(sha3_ctx_t *ctx, uint8_t digest[]);

	uint32_t md_len;     /* message digest bit length */
	uint32_t buf_len;    /* bytes in buffer */
	uint32_t buf_size;   /* the size of buffer in bytes */
	uint64_t state[5][5];
};

void sha3_224_init(sha3_ctx_t *ctx);
void sha3_256_init(sha3_ctx_t *ctx);
void sha3_384_init(sha3_ctx_t *ctx);
void sha3_512_init(sha3_ctx_t *ctx);

void shake128_init(sha3_ctx_t *ctx);
void shake256_init(sha3_ctx_t *ctx);
void shake_update(sha3_ctx_t *ctx, uint8_t *data, size_t len);
void shake_xof(sha3_ctx_t *ctx);
void shake_out(sha3_ctx_t *ctx, uint8_t out[], size_t len);

#endif /* __SHA3_H__ */

