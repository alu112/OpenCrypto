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

#ifndef __RSASSA_PSS_H__
#define __RSASSA_PSS_H__

#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "sha3.h"
#include "rsa.h"

/* salt_len is -1..hash_length */
#define RSA_PSS_SALTLEN_DIGEST -1  /* salt length = hash digest length */

typedef struct rsassa_pss_ctx rsassa_pss_ctx_t;

/* rsa_nbits is the length in bits of RSA modulus n */
struct rsassa_pss_ctx {
        int (*init)(rsassa_pss_ctx_t *ctx, int rsa_nbits, enum hash_id hash_id);
        int (*encodepad)(rsassa_pss_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, uint8_t *em);
	int (*decodepad)(rsassa_pss_ctx_t *ctx, size_t msglen, uint8_t *msg, int salt_len, int emlen, uint8_t *em);

        int k; /* the length of rsa modulus N in bytes */
	int nbits;

        enum hash_id hash_id;
        sha_ctx_t  hash;
};

int rsassa_pss_init(rsassa_pss_ctx_t *ctx, int rsa_nbits, enum hash_id hash_id);

#endif

