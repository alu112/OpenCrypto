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

#ifndef __BN_GF2M_H__
#define __BN_GF2M_H__

#include "bn-gfp.h"

/* galois field(2^m) operation */

/* addition: r = a + b */
void bn_add_gf2m(bn_t a, bn_t b, bn_t r);
/* addition modulo: r = a + b mod n */
void bn_addmod_gf2m(bn_t a, bn_t b, bn_t n, bn_t r);
/* subtraction: r = a - b */
void bn_sub_gf2m(bn_t a, bn_t b, bn_t r);
/* subtraction modulo: r = a - b mod n */
void bn_submod_gf2m(bn_t a, bn_t b, bn_t n, bn_t r);
/* multiplication: r = a * b */
void bn_mul_gf2m(bn_t a, bn_t b, bn_t r);
/* multiplication modulo: r = a * b mod n */
void bn_mulmod_gf2m(bn_t a, bn_t b, bn_t n, bn_t r);
/* division: q = x / n, r = x % n */
void bn_div_gf2m(bn_t x, bn_t n, bn_t q, bn_t r);
/* inversion y = 1/x mod n */
void bn_invmod_gf2m(bn_t x, bn_t n, bn_t y);
/* reduction y = x mod n */
void bn_mod_gf2m(bn_t x, bn_t n, bn_t y);

#endif /* __BN_GF2M_H__ */

