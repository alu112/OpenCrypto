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

#ifndef __SHA_COMMON_H__
#define __SHA_COMMON_H__

#include <stdint.h>
#include <stddef.h>

#define SHA1_DIGEST_LENGTH    160
#define SHA224_DIGEST_LENGTH  224
#define SHA256_DIGEST_LENGTH  256
#define SHA384_DIGEST_LENGTH  384
#define SHA512_DIGEST_LENGTH  512


#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define SHR(x, n)       ((x)>>(n))
#define ROTR32(x, n)    ((x)>>(n) | (x)<<(32-(n)))
#define ROTL32(x, n)    ((x)<<(n) | (x)>>(32-(n)))
#define ROTR64(x, n)    ((x)>>(n) | (x)<<(64-(n)))
#define ROTL64(x, n)    ((x)<<(n) | (x)>>(64-(n)))

typedef __uint128_t  uint128_t;

/*
 * This struct sha_ctx is an common structure for sha-1,2,3
 * 
 * This structure has the maximum size of all shaX structures
 */

#define SHA_BUF_SIZE       128
#define SHA_DIGEST_LENGTH  SHA512_DIGEST_LENGTH

typedef struct sha_ctx sha_ctx_t;

struct sha_ctx {
        void (*init)(sha_ctx_t *ctx);
        void (*update)(sha_ctx_t *ctx, uint8_t *data, size_t len);
        void (*final)(sha_ctx_t *ctx, uint8_t digest[]);

        uint32_t md_len;     /* message digest bit length */
        uint32_t buf_len;    /* bytes in buffer */
        uint32_t buf_size;   /* the size of buffer in bytes */

	/* private for each sha algorithm */
	uint8_t place_holder[218]; /* the size of total + state + buffer */
};


enum hash_id {
        /* sha1 */ eHASH_SHA1,
        /* sha2 */ eHASH_SHA224, eHASH_SHA256, eHASH_SHA384, eHASH_SHA512, eHASH_SHA512_224, eHASH_SHA512_256,
        /* sha3 */ eHASH_SHA3_224, eHASH_SHA3_256, eHASH_SHA3_384, eHASH_SHA3_512
};

typedef struct hash_algo hash_algo_t;

struct hash_algo {
        enum hash_id hash_id;
        void (*init)(sha_ctx_t *);
};
extern hash_algo_t __start_hash_algo;
extern hash_algo_t __stop_hash_algo;
#define REGISTER_HASH_ALGO(id, init) hash_algo_t __attribute((__section__("hash_algo")))  __attribute((__used__)) \
	algo_ ## id = {id, (void (*)(sha_ctx_t *))init};
int hash_init(enum hash_id hash_id, sha_ctx_t *sha);

uint32_t  swap32(uint32_t n);
uint64_t  swap64(uint64_t n);
uint128_t swap128(uint128_t n);

/* hex string to byte array */
int hex2ba(uint8_t *hexstring, uint8_t *byte_array, int max_bytes);
/*
 * byte array to hexstring
 * hex buffer must be at least 2n+1 bytes long
 */
uint8_t *ba2hex(uint8_t *bytes, int nbytes, uint8_t *hex);

#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "sha3.h"

#endif /* __SHA_COMMON_H__ */

