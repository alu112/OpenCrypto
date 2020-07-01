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

#ifndef __RSAES_PKCS1_H__
#define __RSAES_PKCS1_H__

#include "sha-common.h"
#include "rsa.h"

typedef struct rsaes_pkcs1_ctx rsaes_pkcs1_ctx_t;

/* rsa_nbits is the length in bits of RSA modulus n */
struct rsaes_pkcs1_ctx {
        int (*init)(rsaes_pkcs1_ctx_t *ctx, int rsa_nbits, enum hash_id not_used);
        int (*encodepad)(rsaes_pkcs1_ctx_t *ctx, size_t msglen, uint8_t *msg, uint8_t *em);
        int (*decodepad)(rsaes_pkcs1_ctx_t *ctx, int emlen, uint8_t *em, int *outlen, uint8_t *out);

        int k; /* the length of rsa modulus N in bytes */
};

int rsaes_pkcs1_init(rsaes_pkcs1_ctx_t *ctx, int rsa_nbits, enum hash_id hash_id);

#endif

