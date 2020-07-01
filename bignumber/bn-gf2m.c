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
#include "bn-gfp.h"
#include "bn-gf2m.h"

void bn_add_gf2m(bn_t a, bn_t b, bn_t r)
{
	int i, m, n;
	bn_t sum;

	m = bn_getlen(a);
	n = bn_getlen(b);
	n = m<n ? n : m;
	n = n<BN_LEN ? n+1 : BN_LEN;

	bn_clear(sum);
	for (i=0; i<n; i++) {
		sum[i] = a[i] ^ b[i];
	}
	bn_cpy(sum, r);
}

/* galois field(2^m) addition is modulo 2, r = a + b mod n */
void bn_addmod_gf2m(bn_t a, bn_t b, bn_t n, bn_t r)
{
	bn_t sum;

	bn_add_gf2m(a, b, sum);
	bn_mod_gf2m(sum, n, r);
}

void bn_sub_gf2m(bn_t a, bn_t b, bn_t r)
{
	bn_add_gf2m(a, b, r);
}

void bn_submod_gf2m(bn_t a, bn_t b, bn_t n, bn_t r)
{
	bn_addmod_gf2m(a, b, n, r);
}

/* galois field(2^m) multiplication r = a * b */
void bn_mul_gf2m(bn_t a, bn_t b, bn_t r)
{
        int i, len;
        bn_t u, v, y;

        bn_cpy(a, u);
        bn_cpy(b, v);
        bn_clear(y);
        len = bn_getmsbposn(v);
        for (i=0; i<len; i++) {
                if (bn_getbit(v, i)) {
                        bn_add_gf2m(u, y, y);
                }
                bn_lshift1(u);
        }
        bn_cpy(y, r);
}

/* galois field(2^m) multiplication r = a * b mod n*/
void bn_mulmod_gf2m(bn_t a, bn_t b, bn_t n, bn_t r)
{
#if 1
	bn_t y;

	bn_mul_gf2m(a, b, y);
	bn_mod_gf2m(y, n, r);
#else
	/* something not right */
	int i, len, degree_n;
	bn_t n1, u, v, y;

	degree_n = bn_getmsbposn(n);
	bn_cpy(n, n1);
	bn_lshift1(n1);

	bn_cpy(a, u);
	bn_cpy(b, v);
	bn_clear(y);
	len = bn_getmsbposn(v);
	for (i=0; i<len; i++) {
		if (bn_getbit(v, i)) {
			bn_addmod_gf2m(u, y, n, y);
		}
		bn_lshift1(u);
		/* modulo reduction with n1 */
		if (bn_getmsbposn(u) > degree_n) {
			bn_addmod_gf2m(u, n1, n, u);
		}
		if (bn_getmsbposn(u) == degree_n) {
			bn_addmod_gf2m(u, n, n, u);
		}
	}

	bn_cpy(y, r);
#endif
}

/* https://dspace.library.uvic.ca/bitstream/handle/1828/9023/Zhou_Fan_MEng_2018.pdf?sequence=1&isAllowed=y */
/* q = x / n; r = x % n */
void bn_div_gf2m(bn_t x, bn_t n, bn_t q, bn_t r)
{
	int delta;
	int df, da, dr;
	bn_t a, f, r0, q0, one;

	if (bn_cmp(x, n) < 0) {
		bn_clear(q);
		bn_cpy(x, r);
		return;
	}
	bn_setone(one);
	bn_cpy(x, f);
	bn_cpy(n, a);
	bn_setone(r0);
	bn_setone(q0);
	df = bn_getmsbposn(f);
	da = bn_getmsbposn(a);
	while ((delta = df - da) >= 0) {
		bn_lshift(a, delta, r0);
		bn_add_gf2m(r0, f, r0);
		dr = bn_getmsbposn(r0);
		delta = dr - da;
		if (delta >= 0) {
			bn_lshift(q0, df - dr, q0);
			bn_add(q0, one, q0);
		}
		else 
			bn_lshift(q0, df - da, q0);
		bn_cpy(r0, f);
		df = dr;
	}

	/* verify */
	bn_mul_gf2m(n, q0, a);
	bn_add_gf2m(a, r0, a);
	assert(!bn_cmp(a, x));
	/* end of verify */
	bn_cpy(q0, q);
	bn_cpy(r0, r);
}

/* https://www.lirmm.fr/arith18/papers/kobayashi-AlgorithmInversionUsingPolynomialMultiplyInstruction.pdf Algorithm 2*/
/* galois field(2^m) inversion y = 1/x mod n*/
void bn_invmod_gf2m_0(bn_t x, bn_t n, bn_t y)
{
        int delta;
        bn_t s, r, u, v, h;

        bn_cpy(x, r);
        bn_cpy(n, s);
        bn_clear(v);
        bn_setone(u);
        while(bn_getmsbposn(r)>1) {
                delta = bn_getmsbposn(s) - bn_getmsbposn(r);
                if (delta < 0) {
                        delta = -delta;
                        bn_swap(s, r);
                        bn_swap(u, v);
                }
                bn_lshift(r, delta, h);
                bn_submod_gf2m(s, h, n, s);
                bn_lshift(u, delta, h);
                bn_submod_gf2m(v, h, n, v);
        }
	assert(bn_isone(r));
        bn_cpy(u, y);
}

/* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf Appendix B.1 */
void bn_invmod_gf2m(bn_t x, bn_t n, bn_t invx)
{
	bn_t i, j, y2, y1, y, q, r;

	//assert(bn_cmp(x, n) < 0);

	bn_cpy(x, j);
	bn_cpy(n, i);
	bn_clear(y2);
	bn_setone(y1);

	while (bn_ispositive(j)) {
		bn_div_gf2m(i, j, q, r);
		bn_mul_gf2m(y1, q, y);
		bn_sub_gf2m(y2, y, y);

		bn_cpy(j, i);
		bn_cpy(r, j);
		bn_cpy(y1, y2);
		bn_cpy(y, y1);
	}
	assert(bn_isone(i));
	bn_cpy(y2, invx);
}

/* reduction y = x mod n */
void bn_mod_gf2m(bn_t x, bn_t n, bn_t y)
{
	int i, j;
	bn_t a, m;

	bn_cpy(x, a);
	i = bn_getmsbposn(a);
	j = bn_getmsbposn(n);
	while (i >= j) {
		bn_lshift(n, i-j, m);
		bn_add_gf2m(a, m, a);
		i = bn_getmsbposn(a);
	}
	bn_cpy(a, y);
}


/* http://mathforum.org/library/drmath/view/51675.html 

Now suppose one of the entries in your matrix is the byte 11001001.
You have to figure out whether this means

     f(x) = x^7 + x^6 + x^3 + 1

Given a polynomial a(x) whose inverse you seek, perform the Extended 
Euclidean Algorithm on a(x) and f(x). If a(x) is not zero, you will 
obtain polynomials r(x) and s(x) such that

     r(x)*a(x) + s(x)*f(x) = 1

Then reduce this equation modulo f(x):

     r(x)*a(x) = 1 (mod f(x))

a(x) will be the multiplicative inverse of r(x).

Example: Inverse of x^4 + 1.


You can keep tracking of some
auxiliary quantities as you perform the Euclidean Algorithm.

     Remainder        Quotient     Auxiliary
     x^8+x^6+x^5+x+1               0
     x^4+1                         1
     x^2              x^4+x^2+x+1  x^4+x^2+x+1
     1                x^2          x^6+x^4+x^3+x^2+1

The Auxiliary column always starts with 0 and 1. The Remainder column
always starts with f(x) and a(x). To fill in any subsequent row,
divide the remainders in the previous two rows, and put the quotient
in the Quotient column and the remainder in the Remainder column. Then
multiply the quotient times the Auxiliary number in the previous row
and add the Auxiliary number in the row before that, putting the
result in the Auxiliary column. When the remainder is reduced to 1,
the content of the Auxiliary column in that row is the inverse of
a(x). This is a version of the Extended Euclidean Algorithm which you
can use to advantage here.
*/

