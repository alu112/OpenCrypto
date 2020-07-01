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

#ifndef __GFP_H__
#define __GFP_H__

#include "bn.h"


typedef struct gfp_point {
	bn_t x;
	bn_t y;
} gfp_point_t;


typedef struct gfp_curve {
	bn_t prime; /* this is actually polynomial */
	bn_t a;
	bn_t b;
	gfp_point_t g;
	bn_t order;
	bn_t cofactor;
	bn_t seed;
	uint32_t keylen;
} gfp_curve_t;

void gfp_print(char *msg, gfp_point_t *p);
void gfp_assign(gfp_point_t *from, gfp_point_t *to);
bool gfp_isequal(gfp_point_t *p, gfp_point_t *q);

/* add two points in prime field: R = P + Q mod N, P <> Q */
void gfp_addmod(gfp_point_t *p, gfp_point_t *q, gfp_curve_t *ec, gfp_point_t *r);

/* double a point in prime field: R = 2P mod N, P == Q */
void gfp_dblmod(gfp_point_t *p, gfp_curve_t *ec, gfp_point_t *r);

/* multiplies a point in prime field with a scalar number: R = kP mod N */
void gfp_mulmod(gfp_point_t *p, bn_t k, gfp_curve_t *ec, gfp_point_t *r);

#endif /* __GFP_H__ */

