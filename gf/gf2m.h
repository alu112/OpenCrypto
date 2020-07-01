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

#ifndef __GF2M_H__
#define __GF2M_H__

#include "bn.h"
#include "gfp.h"

/* check if y^2 + x*y = x^3 + a*x^2 + b, (b<>0) holds */
bool gf2m_oncurve(gfp_point_t *p, gfp_curve_t *ec);

/* add two points in GF(2m) field */
void gf2m_addmod(gfp_point_t *p, gfp_point_t *q, gfp_curve_t *ec, gfp_point_t *r);

/* double a point in GF(2m) field */
void gf2m_dblmod(gfp_point_t *p, gfp_curve_t *ec, gfp_point_t *r);

/* multiplies a point in GF(2m) field with a scalar number */
void gf2m_mulmod(gfp_point_t *p, bn_t k, gfp_curve_t *ec, gfp_point_t *r);

#endif /* __GF2M_H__ */

