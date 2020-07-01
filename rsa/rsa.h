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

#ifndef __RSA_H__
#define __RSA_H__

#include <stdint.h>
#include "bn.h"

typedef struct rsa_key {
	int keybits; /* key lengths in bits */
        bn_t n, e, d, p, q, dp, dq, invq;
} rsa_key_t;

/* all functions return 0 if succeeded, otherwise failed */

/* special value to parameter *e of rsa_keygen() */
#define USE_PQE_IN_PRV NULL
#define GET_SAFE_PRIME ((void *)1)
int  rsa_keygen (int keybits, uint8_t *e,   rsa_key_t *prv, rsa_key_t *pub);
int  rsa_encrypt(rsa_key_t *pub, uint8_t *msg, int bytes, uint8_t *cipher);
int  rsa_decrypt(rsa_key_t *prv, uint8_t *cipher, int bytes, uint8_t *msg);
int  rsa_sign(rsa_key_t *prv, uint8_t *em, int em_bytes, uint8_t *signature);
int  rsa_verify(rsa_key_t *pub, uint8_t *signature, int sign_bytes, uint8_t *em);

#endif /* __RSA_H__ */

