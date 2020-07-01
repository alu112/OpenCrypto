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

#ifndef __DSA_H__
#define __DSA_H__

#include "bn.h"


typedef struct dsa_param dsa_param_t;

struct dsa_param {
	bn_t p; /* prime */
	bn_t q; /* prime divisor */
	bn_t g; /* group generator */
	uint32_t keylen; /* bit length */
};

typedef struct dsa_key {
	bn_t prv; /* private key */
	bn_t pub; /* public key */
	dsa_param_t dsa; /* p,q,g */
} dsa_key_t;

typedef struct {
	bn_t sig; /* signature */
	bn_t r;	  /* (g^Ke mod p)mod q */
} dsa_sig_t;

void dsa_keygen(uint32_t keylen, dsa_key_t *key);
void dsa_sign(dsa_key_t *key, uint8_t *hash, uint32_t hlen, dsa_sig_t *sign);
bool dsa_verify(dsa_key_t *key, uint8_t *hash, uint32_t hlen, dsa_sig_t *sign);


#endif /* __DSA_H__ */

