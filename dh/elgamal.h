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

#ifndef __ELGAMAL_H__
#define __ELGAMAL_H__

#include "bn.h"

typedef struct {
	bn_t p;	    /* prime */
	bn_t g;	    /* group generator */
	bn_t x;	    /* g^d mod p */
} elg_pubkey_t;


typedef struct {
	bn_t p;	    /* prime */
	bn_t g;	    /* group generator */
	bn_t x;	    /* g^d mod p */
	bn_t d;	    /* secret exponent */
} elg_prvkey_t;

void elg_keygen(elg_prvkey_t *prv);
void elg_encrypt(uint8_t *msg, elg_pubkey_t *prv, uint8_t *ke, uint8_t *cipher);
void elg_decrypt(uint8_t *ke, uint8_t *cipher, elg_prvkey_t *prv, uint8_t *msg);

#endif /* __ELGAMAL_H__ */

