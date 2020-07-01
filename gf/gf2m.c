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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "gf2m.h"

/* check if y^2 + x*y = x^3 + a*x^2 + b, (b<>0) holds */
bool gf2m_oncurve(gfp_point_t *p, gfp_curve_t *ec)
{
	bn_t a, b;

	if (bn_iszero(p->x))
	{
		return true;
	}
	else
	{
		/* (x + a) * x^2 + b */
		bn_mulmod_gf2m(p->x, p->x, ec->prime, a);
		if (bn_iszero(ec->a))
			bn_mulmod_gf2m(a, p->x, ec->prime, a);
		else {
			bn_addmod_gf2m(ec->a, p->x, ec->prime, b);
			bn_mulmod_gf2m(b, a, ec->prime, a);
		}
		bn_addmod_gf2m(a, ec->b, ec->prime, a);
		/* (x + y) * y */
		bn_addmod_gf2m(p->x, p->y, ec->prime, b);
		bn_mulmod_gf2m(b, p->y, ec->prime, b);

		return !bn_cmp(a, b);
	}
}

/* http://www.just.edu.jo/~tawalbeh/nyit/csci860/notes/ec1.pdf   page 10 */
/* add two points in GF(2m) field: R = P + Q mod N, P <> Q */
void gf2m_addmod(gfp_point_t *p, gfp_point_t *q, gfp_curve_t *ec, gfp_point_t *r)
{
	bn_t dx, idx, dy, s, ss, x3, y3;

	/*
	 * O + O = O
	 * (x,y) + O = (x,y)
	 * (x,y) + (x,x+y) = O
	 */
	if (bn_iszero(p->x) && bn_iszero(p->y)) {
		gfp_assign(q, r);
		return;
	}
	if (bn_iszero(q->x) && bn_iszero(q->y)) {
		gfp_assign(p, r);
		return;
	}
	if (!bn_cmp(p->x, q->x)) {
		bn_addmod_gf2m(p->y, q->y, ec->prime, y3);
		if (!bn_cmp(p->x, y3)) {
			bn_clear(r->x);
			bn_clear(r->y);
			return;
		}
	}

	bn_addmod_gf2m(p->x, q->x, ec->prime, dx);  /* dx = x1 + x2 */
	bn_addmod_gf2m(p->y, q->y, ec->prime, dy);  /* dy = y1 + y2 */
	bn_invmod_gf2m(dx, ec->prime, idx);         /* idx = 1/(x1 + x2) */
	bn_mulmod_gf2m(dy, idx, ec->prime, s);      /* s = (y1 + y2) / (x1 + x2) */
	bn_mulmod_gf2m(s, s, ec->prime, ss);        /* s^2 */

	/* x3 = s^2 + s + dx + ec->a */
	bn_addmod_gf2m(ss, s, ec->prime, x3);
	bn_addmod_gf2m(x3, dx, ec->prime, x3);
	bn_addmod_gf2m(x3, ec->a, ec->prime, x3);
	/* y3 = s(p->x + x3) + x3 + p->y */
	bn_addmod_gf2m(x3, p->x, ec->prime, y3);
	bn_mulmod_gf2m(y3, s, ec->prime, y3);
	bn_addmod_gf2m(y3, x3, ec->prime, y3);
	bn_addmod_gf2m(y3, p->y, ec->prime, y3);

	bn_cpy(x3, r->x);
	bn_cpy(y3, r->y);
	assert(gf2m_oncurve(r, ec));
}

/* https://cse.iitkgp.ac.in/~abhij/course/theory/CNT/Spring18/DM/FastECCCHES99.pdf */
void gf2m_dblmod_new(gfp_point_t *p, gfp_curve_t *ec, gfp_point_t *r)
{
	bn_t invx, invxx, xx, x3, y3;

	bn_mulmod_gf2m(p->x, p->x, ec->prime, xx);
	bn_invmod_gf2m(p->x, ec->prime, invx);
	/* x3 = x^2 + b/(x^2) */
	bn_mulmod_gf2m(invx, invx, ec->prime, invxx);
	bn_mulmod_gf2m(ec->b, invxx, ec->prime, x3);
	bn_addmod_gf2m(xx, x3, ec->prime, x3);
	/* y3 = x^2 + (x + y/x)x3 + x3 */
	bn_mulmod_gf2m(p->y, invx, ec->prime, y3);
	bn_addmod_gf2m(y3, p->x, ec->prime, y3);
	bn_mulmod_gf2m(y3, x3, ec->prime, y3);
	bn_addmod_gf2m(y3, x3, ec->prime, y3);
	bn_addmod_gf2m(y3, xx, ec->prime, y3);
	bn_cpy(x3, r->x);
	bn_cpy(y3, r->y);
}

/* http://www.just.edu.jo/~tawalbeh/nyit/csci860/notes/ec1.pdf   page 10 */
/* double a point in GF(2m) field: R = 2P mod N, P == Q */
void gf2m_dblmod_old(gfp_point_t *p, gfp_curve_t *ec, gfp_point_t *r)
{
	bn_t s, ss, xx, x3, y3;

	if (bn_iszero(p->x) && bn_iszero(p->y)) {
		bn_clear(r->x);
		bn_clear(r->y);
		return;
	}
	
	/* s = x + y/x */
	bn_invmod_gf2m(p->x, ec->prime, s);
	bn_mulmod_gf2m(s, p->y, ec->prime, s);
	bn_addmod_gf2m(s, p->x, ec->prime, s);
	bn_mulmod_gf2m(s, s, ec->prime, ss);
	/* x3 = s^2 + s + a */
	bn_addmod_gf2m(ss, s, ec->prime, x3);
	bn_addmod_gf2m(x3, ec->a, ec->prime, x3);
	/* y3 = x^2 + (s + 1)x */
	bn_setone(xx);
	bn_addmod_gf2m(s, xx, ec->prime, y3);
	bn_mulmod_gf2m(y3, x3, ec->prime, y3);
	bn_mulmod_gf2m(p->x, p->x, ec->prime, xx);
	bn_addmod_gf2m(xx, y3, ec->prime, y3);

	bn_cpy(x3, r->x);
	bn_cpy(y3, r->y);
	assert(gf2m_oncurve(r, ec));
}

void gf2m_dblmod(gfp_point_t *p, gfp_curve_t *ec, gfp_point_t *r)
{
	gfp_point_t r1;
	gf2m_dblmod_old(p, ec, &r1);
	gf2m_dblmod_new(p, ec, r);
	assert(!bn_cmp(r1.x, r->x));
	assert(!bn_cmp(r1.y, r->y));
}

/* multiplies a point in GF(2m) field with a scalar number: R = kP mod N */
void gf2m_mulmod(gfp_point_t *p, bn_t k, gfp_curve_t *ec, gfp_point_t *r)
{
	int i, j;
	gfp_point_t q;

	i = bn_getmsbposn(k) - 1;
	j = i % 32;
	i /= 32;

	gfp_assign(p, &q);

	for (j--; i>=0; i--) {
		for (; j>=0; j--) {
			gf2m_dblmod(&q, ec, &q);
			if (k[i] & (1<<j)) {
				gf2m_addmod(&q, p, ec, &q);
			}
		}
		j = 31;
	}
	gfp_assign(&q, r);
	assert(gf2m_oncurve(r, ec));
}

