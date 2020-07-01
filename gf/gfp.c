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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "gfp.h"


void gfp_assign(gfp_point_t *from, gfp_point_t *to)
{
	bn_cpy(from->x, to->x);
	bn_cpy(from->y, to->y);
}

void gfp_print(char *msg, gfp_point_t *p)
{
	printf("%s\n", msg);
	bn_print("x=", p->x);
	bn_print("y=", p->y);
}

bool gfp_isequal(gfp_point_t *p, gfp_point_t *q)
{
	return (!bn_cmp(p->x, q->x) && !bn_cmp(p->y, q->y));
}

/* add two points in prime field: R = P + Q mod N, P <> Q */
void gfp_addmod(gfp_point_t *p, gfp_point_t *q, gfp_curve_t *ec, gfp_point_t *r)
{
	bn_t z, sz, rx, idx, dx, dy, s, ss;

	if (bn_iszero(p->x) && bn_iszero(p->y)) {
		gfp_assign(q, r);
		return;
	}
	if (bn_iszero(q->x) && bn_iszero(q->y)) {
		gfp_assign(p, r);
		return;
	}
	if (!bn_cmp(p->x, q->x)) {
		bn_addmod(p->y, q->y, ec->prime, z);
		if (bn_iszero(z)) {
			bn_clear(r->x);
			bn_clear(r->y);
			return;
		}
	}
	bn_submod(p->x, q->x, ec->prime, dx);  /* dx = x1 - x2 */
	bn_submod(p->y, q->y, ec->prime, dy);  /* dy = y1 - y2 */
	bn_invmod(dx, ec->prime, idx);         /* idx = 1/(x1 - x2) */
	bn_mulmod(dy, idx, ec->prime, s);      /* s = (y1 - y2) / (x1 - x2) */

	bn_addmod(p->x, q->x, ec->prime, z);   /* z = x1 + x2 */

	bn_mulmod(s, s, ec->prime, ss);        /* s^2 */
	bn_submod(ss, z, ec->prime, rx);       /* rx = s^2 - x1 - x2 */
	bn_submod(p->x, rx, ec->prime, z);     /* z = x1 - rx */
	bn_mulmod(s, z, ec->prime, sz);        /* sz = s(x1 - rx) */
	bn_submod(sz, p->y, ec->prime, r->y);  /* r->y = s(x1 - rx) - y1 */
	bn_cpy(rx, r->x);                      /* r->x = rx */
}

/* double a point in prime field: R = 2P mod N, P == Q */
void gfp_dblmod(gfp_point_t *p, gfp_curve_t *ec, gfp_point_t *r)
{
	bn_t z, sz, xx, rx, y2, iy2, s, ss, three;

	bn_qw2bn(3, three);
	bn_mulmod(p->x, p->x, ec->prime, xx);  /* xx = x^2 */
	bn_mulmod(xx, three, ec->prime, xx);   /* xx = 3x^2 */
	bn_addmod(xx, ec->a, ec->prime, xx);   /* xx = 3x^2 + a */
	bn_addmod(p->y, p->y, ec->prime, y2);  /* y2 = 2*y */
	bn_invmod(y2, ec->prime, iy2);         /* iy2 = 1/(2y) */
	bn_mulmod(xx, iy2, ec->prime, s);      /* s = (3x^2+a)/(2y) */

	bn_addmod(p->x, p->x, ec->prime, z);   /* z = x + x */

	bn_mulmod(s, s, ec->prime, ss);        /* ss = s^2 */
	bn_submod(ss, z, ec->prime, rx);       /* rx = s^2 - 2x */
	bn_submod(p->x, rx, ec->prime, z);     /* z = x1 - rx */
	bn_mulmod(s, z, ec->prime, sz);        /* sz = s * z */
	bn_submod(sz, p->y, ec->prime, r->y);  /* r->y = s(x1 - rx) - y */
	bn_cpy(rx, r->x);                      /* r->x = rx */
}

/* multiplies a point in prime field with a scalar number: R = kP mod N */
void gfp_mulmod(gfp_point_t *p, bn_t k, gfp_curve_t *ec, gfp_point_t *r)
{
	int i, j;
	gfp_point_t t;

	i = bn_getlen(k) - 1;
	for (j=31; j>=0; j--) {
		if (k[i] & (1<<j)) break;
	}
	j--;

	gfp_assign(p, &t);

	for (; i>=0; i--) {
		for (; j>=0; j--) {
			gfp_dblmod(&t, ec, &t);
			if (k[i] & (1<<j)) {
				gfp_addmod(&t, p, ec, &t);
			}
		}
		j = 31;
	}
	gfp_assign(&t, r);
}

