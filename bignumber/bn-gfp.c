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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "bn-gfp.h"

#if 1
void (*bn_expmod)(bn_t, bn_t, bn_t, bn_t) =  bn_kary_expmod; /* bn_bitwise_expmod; bn_kary_expmod; */
//void (*bn_expmod)(bn_t, bn_t, bn_t, bn_t) =  bn_bitwise_expmod; /* bn_bitwise_expmod; bn_kary_expmod; */
void (*bn_mulmod)(bn_t, bn_t, bn_t, bn_t) = bn_classic_mulmod; /* bn_mont_mulmod; bn_classic_mulmod */
#else
void (*bn_expmod)(bn_t, bn_t, bn_t, bn_t) = bn_mont_expmod;
void (*bn_mulmod)(bn_t, bn_t, bn_t, bn_t) = bn_mont_mulmod;
#endif
void (*bn_div)(bn_t, bn_t, bn_t, bn_t) = bn_hac_div; /* bn_hac_div; bn_classic_div */
void (*bn_mont_pro)(bn_t , bn_t , bn_t , bn_t , bn_t ) = bn_mont_pro_2;

static void r_mod_n(bn_t r, bn_t n, bn_t r_n);

void bn_print(char * msg, bn_t bn)
{
	int i;
	uint8_t *p8 = (uint8_t *)bn;

	if (msg) printf("%s", msg);
	for (i=BN_LEN*4-1; i>=0; i--)
		if (p8[i]) break;
	i = i < 0 ? 0 : i;
	for ( ; i>=0; i--)
		printf("%02x", p8[i]);
	printf("\n");
}

/* print n bytes */
void bn_print_len(char *msg, bn_t bn, int n)
{
	int i;
	uint8_t *p8 = (uint8_t *)bn;

	if (msg) printf("%s", msg);
	/* if n is longer than BN_LEN*4 */
	for (i=n-1; i>=BN_LEN*4-1; i--) printf("00");
	if (n >= BN_LEN*4) i = BN_LEN*4 - 1;
	else i = n - 1;
	for ( ; i>=0; i--) printf("%02x", p8[i]);
	printf("\n");
}

void bn_swap(bn_t a, bn_t b)
{
	bn_t t;
	bn_cpy(a, t);
	bn_cpy(b, a);
	bn_cpy(t, b);
}

int  bn_getbit(bn_t a, int i)
{
	int dword, bits;

	assert(i<BN_LEN*32);
	dword = i / 32;
	bits = i % 32;
	return a[dword] & (1<<bits) ? 1 : 0;
}

void bn_setbit(bn_t a, int i)
{
	int dword, bits;

	assert(i<BN_LEN*32);
	dword = i / 32;
	bits = i % 32;
	a[dword] |= (1<<bits);
}

void bn_clrbit(bn_t a, int i)
{
	int dword, bits;

	assert(i<BN_LEN*32);
	dword = i / 32;
	bits = i % 32;
	a[dword] &= ~(1<<bits);
}

/* get left most uint32 which is not zero */
int bn_getlen(bn_t bn)
{
	int i;

	for (i=BN_LEN-1; i>=0; i--) {
		if (bn[i]) break;
	}
	return i + 1;
}

/* get msbit position */
int bn_getmsbposn(bn_t bn)
{
	int i, j;

	i = bn_getlen(bn) - 1;
	if (i >= 0) {
		for (j=31; j>=0; j--)
			if (bn[i] & (1<<j)) break;
		return i * 32 + j + 1;
	}
	else return 0;
}

/* bn = 0 */
void bn_clear(bn_t bn)
{
	memset(bn, 0, sizeof(bn_t));
}

/* bn = 1 */
void bn_setone(bn_t bn)
{
	bn_clear(bn);
	*(uint32_t *)bn = 1;
}

/* set bn = uint64 */
void bn_qw2bn(uint64_t u64, bn_t bn)
{
	bn_clear(bn);
	memmove(bn, &u64, sizeof(uint64_t));
}

/* set bn to the hexstring */
void bn_hex2bn(uint8_t *hexstr, bn_t bn)
{
	int i, k, len,  offset;
	uint8_t hex[16];

	bn_clear(bn);
	if (!strncmp(hexstr, "0x", 2) || !strncmp(hexstr, "0X", 2))
		hexstr += 2;
	len = strlen(hexstr);
	for (k=0, i=0; i<len; k++, i+=8) {
		memset(hex, 0, sizeof(hex));
		offset = len - i - 8;
		if (offset > 0)
			memmove(hex, &hexstr[offset], 8);
		else
			memmove(hex, hexstr, len - i);
		bn[k] = strtoul(hex, 0, 16);
	}
}

void bn_bn2hex(bn_t a, uint8_t *hex)
{
	int i, len;

	len = bn_getlen(a);
	strcpy(hex, "0x");
	for (i=0; i<len; i++)
		sprintf(hex+i*8+2, "%08x", a[len-i-1]); 
}

/* copy bytes array to bn */
void bn_ba2bn(uint8_t *bytes, int len, bn_t r)
{
	uint8_t *dst = (uint8_t *)r;
	bn_clear(r);
	bytes += len-1;
	while(len--)
		*dst++ = *bytes--;
}

void bn_bn2ba(bn_t r, int len, uint8_t *bytes)
{
	uint8_t *src = (uint8_t *)r;

	bytes += len-1;
	while(len--)
		*bytes-- = *src++;
}

bool bn_iszero(bn_t bn)
{
	int i;
	uint32_t u32 = 0;

	for (i=0; i<BN_LEN; i++)
		u32 |= bn[i];
	return u32 ? 0 : 1;
}

bool bn_isone(bn_t bn)
{
	int i;
	uint32_t u32;

	if (*bn == 1) {
		u32 = 0;
		for (i=1; i<BN_LEN; i++)
			u32 |= bn[i];
		return !u32;
	}
	return false;
}

bool bn_isodd(bn_t bn)
{
	return bn[0] & 1 ? 1 : 0;
}

bool bn_iseven(bn_t bn)
{
	return bn[0] & 1 ? 0 : 1;
}
/* no negative number */
bool bn_ispositive(bn_t bn)
{
	return !bn_iszero(bn);
}

/* to = from */
void bn_cpy(bn_t from, bn_t to)
{
	memmove(to, from, sizeof(bn_t));
}

/* copy [from] n uint32 start from offset to [to] */
void bn_cpylen(int offset, int n, bn_t from, bn_t to)
{
	memset(to, 0, sizeof(bn_t));
	memmove(to, from + offset - n + 1, 4*n);
}

/* b = a << nbits */
void bn_lshift(bn_t a, int nbits, bn_t b)
{
	int i;
	int nwords = (nbits / 32);

	memmove(b+nwords, a, (BN_LEN-nwords)*sizeof(uint32_t));
	memset(b, 0, nwords*sizeof(uint32_t));

	nbits &= 31;
	if (nbits)
	{
		for (i = BN_LEN - 1; i > 0; i--)
			b[i]  = (b[i] << nbits) | (b[i - 1] >> (32 - nbits));
		b[0] <<= nbits;
	}
}

/* b = a >> nbits */
void bn_rshift(bn_t a, int nbits, bn_t b)
{
	int i;
	int nwords = (nbits / 32);

	memmove(b, a+nwords, (BN_LEN-nwords)*sizeof(uint32_t));
	memset(b+BN_LEN - nwords, 0, nwords*sizeof(uint32_t));

	nbits &= 31;
	if (nbits)
	{
		for (i = 0; i < BN_LEN - 2; i++)
			b[i]  = (b[i] >> nbits) | (b[i + 1] << (32 - nbits));
		b[BN_LEN - 1] >>= nbits;
	}
}

/* bn <<= 32 */
void bn_lshift32(bn_t bn)
{
	int i;

	for (i=BN_LEN-1; i>0; i--)
		bn[i] = bn[i-1];
	bn[0] = 0;
}

/* bn = bn<<32 | u32 */
void bn_lshift32_append(bn_t bn, uint32_t u32)
{
	bn_lshift32(bn);
	bn[0] = u32;
}

/* bn <<= 1 , which is bn*2 */
void bn_lshift1(bn_t bn)
{
	int i;
	uint32_t bl, br;

	bl = 0;
	for (i=0; i<BN_LEN; i++) {
		br = bn[i] >> 31 & 1;
		bn[i] = bn[i] << 1 | bl;
		bl = br;
	}
}

/* bn >>= 1 , which is bn/2 */
void bn_rshift1(bn_t bn)
{
	int i;
	uint32_t bl, br;

	bl = 0;
	for (i=BN_LEN-1; i>=0; i--) {
		br = (bn[i] & 1) << 31;
		bn[i] = bn[i] >> 1 | bl;
		bl = br;
	}
}

/* a = a + uint32 */
uint32_t bn_addx(uint32_t x, bn_t a)
{
	int i;

	if (a[0] + x < x) {
		for (i=1; i<BN_LEN; i++)
			if (++a[i]) break;
	}
	a[0] += x;
	if (i == BN_LEN) return 1; /* carry */
	else return 0;
}

/* a = a - uint32 */
uint32_t bn_subx(uint32_t x, bn_t a)
{
	int i;

	if (a[0] < x) {
		for (i=1; i<BN_LEN; i++)
			if (a[i]--) break;
	}
	a[0] -= x;
	if (i == BN_LEN) return 1; /* borrow */
	else return 0;
}

/*
 * return 1: a > b
 *        0: a == b
 *       -1: a < b
 */
int  bn_cmp(bn_t a, bn_t b)
{
	int i;

	for (i=BN_LEN-1; i>=0; i--) {
		if (a[i] > b[i]) return 1;
		else if (a[i] < b[i]) return -1;
	}
	return 0;
}

/* r = a + b */
uint32_t bn_add(bn_t a, bn_t b, bn_t r)
{
#if 0   /* avoid use uint64_t, this is slower */
	int i, m, n;
	uint32_t carry;
	bn_t sum;

	m = bn_getlen(a);
	n = bn_getlen(b);
	n = m<n ? n : m;
	n = n<BN_LEN ? n : BN_LEN;
	carry = 0;
	bn_clear(sum);
	for (i=0; i<n; i++) {
		sum[i] = a[i] + b[i] + carry;
		carry = a[i] > ~b[i] ? 1 : 0;
	}
	if (i<BN_LEN) {
		sum[i] = carry;
		carry = 0;
	}
	bn_cpy(sum, r);
	return carry;
#else
	int i, m, n;
	uint64_t u64;
	bn_t sum;

	m = bn_getlen(a);
	n = bn_getlen(b);
	n = m<n ? n : m;
	n = n<BN_LEN ? n+1 : BN_LEN;
	u64 = 0UL;
	bn_clear(sum);
	for (i=0; i<n; i++) {
		u64 = (u64 >> 32) + (uint64_t)a[i] + (uint64_t)b[i];
		sum[i] = u64;
	}
	u64 >>= 32;
	if (i<BN_LEN) {
		sum[i] = u64;
		u64 = 0;
	}
	bn_cpy(sum, r);
	return u64;
#endif
}

/* r = a - b */
uint32_t bn_sub(bn_t a, bn_t b, bn_t r)
{
	int i;
	bn_t t;

	for (i=0; i<BN_LEN; i++)
		t[i] = ~b[i];
	bn_addx(1, t);
	return bn_add(a, t, r);
}

/* r = a * u32 */
uint32_t bn_mul32(bn_t a, uint32_t u32, bn_t r)
{
	int i, n;
	uint64_t u64 = 0;
	bn_t result;

	n = bn_getlen(a);
	bn_clear(result);
	for (i=0; i</*BN_LEN*/ n; i++) {
		u64 = (u64 >> 32) + a[i] * (uint64_t)u32;
		result[i] = u64;
	}
	u64 >>= 32;
	if (i<BN_LEN) {
		result[i] = u64;
		u64 = 0;
	}
	bn_cpy(result, r);
	/* if u64 is none-zero, then it is the carry value */
	return u64;
}

/* r = a * u64 */
uint64_t bn_mul64(bn_t a, uint64_t u64, bn_t r)
{
	uint64_t carry;
	bn_t u, v;

	carry = bn_mul32(a, u64, u);
	bn_cpy(a, v);
	carry |= (uint64_t)bn_mul32(v, u64>>32, v) << 32;
	carry += v[BN_LEN-1];
	bn_lshift32(v);
	carry += bn_add(u, v, r);
	return carry;
}

/* r = a * b */
uint32_t bn_mul(bn_t a, bn_t b, bn_t r)
{
	int i, j, m, n;
	uint32_t carry;
	uint64_t u64;
	bn_t tmp, res, a1, b1;

	m = bn_getlen(a);
	n = bn_getlen(b);
	m = m<BN_LEN ? m+1 : BN_LEN;
	n = n<BN_LEN ? n+1 : BN_LEN;

	if (m >= n) {
		bn_cpy(a, a1);
		bn_cpy(b, b1);
	}
	else {
		bn_cpy(a, b1);
		bn_cpy(b, a1);
		i = m;
		m = n;
		n = i;
	}

	carry = 0;
	bn_clear(res);
	for (i=0; i<m; i++) {
		u64 = 0UL;
		bn_clear(tmp);
		for (j=0; j<n && i+j<BN_LEN; j++) {
			u64 = (u64>>32) + (uint64_t)a1[i] * b1[j];
			tmp[i+j] = u64;
		}
		carry += u64>>32;
		bn_add(res, tmp, res);
	}
	bn_cpy(res, r);
	return carry;
}

/* HAC 14.16 Algorithm Multiple-precision squaring */
uint32_t bn_sqr(bn_t x, bn_t y)
{
	int i, j, t;
	bn_t w;
	uint64_t uv, c, p, p2, c1;

	t = bn_getlen(x);
	if (t>BN_LEN/2) return -1;

	bn_clear(w);
	for (i=0; i<t; i++) {
		p = (uint64_t)x[i] * x[i];
		w[2*i] = uv = w[2*i] + p;
		c = uv>>32;
		if (uv < p) c |= 1UL<<32;
		for (j=i+1; j<t; j++) {
			p = (uint64_t)x[i] * x[j];
			p2 = p<<1;
			if (p2 < p) c1 = 1UL<<32;
			else c1 = 0;
			uv = w[i+j] + c;
			if (uv < c) c1 += 1UL<<32;
			w[i+j] = uv += p2;
			if (uv < p2) c1 += 1UL<<32;
			c = c1 | uv>>32;
		}
		if (i+j<BN_LEN-1) *(uint64_t *)&w[i+j] += c;
		else w[i+j] += c;
	}
	bn_cpy(w, y);
	return 0;
}

/* q = a / s;  r = a % s */
void bn_divu32(bn_t a, uint32_t s, bn_t q, uint32_t *r)
{
	int i;
	uint64_t u64 = 0UL;
	bn_t y;

	bn_clear(y);
	for (i=BN_LEN-1; i>=0; i--) {
		u64 = u64 << 32 | a[i];
		y[i] = u64 / s;
		u64 %= s;
	}
	bn_cpy(y, q);
	*r = u64;
}

/*
 * q = a / b;  m = a % b 
 * if q and m point to same location
 * then m contain correct value, q is overwritten by m
 */
void bn_classic_div(bn_t a, bn_t b, bn_t q, bn_t m)
{
	int i, alen, blen, nshift = 0;
	uint32_t r32;
	uint64_t rh, rl;
	bn_t  rt, mt, r, mm;
	bn_t at, bt;
	bn_t av, bv;

	bn_cpy(a, at);
	bn_cpy(b, bt);
	bn_cpy(a, av);
	bn_cpy(b, bv);

	switch (bn_cmp(at, bt)) {
		case -1:
			bn_clear(q);
			bn_cpy(at, m);
			break;
		case  0:
			bn_setone(q);
			bn_clear(m);
			break;
		case +1:
			/*
			 * normalize 
			 * if normalized, then the rh-rl <= 2
			 */
			alen = bn_getlen(at) - 1;
			nshift = bn_getmsbposn(bt) % 32;
			if ((alen < BN_LEN - 1) && (nshift != 0)) {
				nshift = 32 - nshift;
				bn_lshift(at, nshift, at);
				bn_lshift(bt, nshift, bt);
			}
			else nshift = 0;
			/* end of normalize */

			alen = bn_getlen(at) - 1;
			blen = bn_getlen(bt) - 1;

			r32 = 0;
			bn_clear(r);
			/* get blen-1 uint32 from at to mm as numerator */
			bn_cpylen(alen, blen, at, mm);
			/* bt is denominator */
			for (i=alen-blen; i>=0; i--) {
				/* 
				 * get in another uint32 to numerator mm
				 * so mm is at least blen length
				 */
				bn_lshift32_append(mm, at[i]);
				/*
				 * if numerator is less than denominator, then the quotient is 0
				 * and have to get another uint32 in to numerator
				 */
				if (bn_cmp(mm, bt) < 0) {
					r32 = 0;
					bn_lshift32_append(r, r32);
					continue;
				}
				/* try to find the scope of quotient */
				/* mm might be 64-bit, and mm+1 also might be 64-bit */
				rh = (*(uint64_t *)&mm[blen]+1UL) / (bt[blen]);
				/*
				 * because at > bt, so bt < 0xFFFFFFFF
				 * so bt + 1 <= 0xFFFFFFFF, it is 32-bit number
				 */
				rl = (*(uint64_t *)&mm[blen]) / (bt[blen] + 1UL);
				/*
				 * although the calculated rh value bigger then uint32
				 * but in reality, the quotient won't be that big.
				 * If this happened, just set the quotient to maximum uint32 number.
				 * Reason:
				 * the *(uint64_t *)&mm[blen] can only contain more than 
				 * 32-bit number if and only if the mm[blen] < bt[blen]
				 *
				 * for an 8-bit example: 
				 * the quotient of 0xBECD / 0xBF is an 8-bit digit + remainder
				 * it won't be more than 8-bit digits
				 */
				assert((rh&0xFFFFFFFe00000000UL)==0);
				assert((rl&0xFFFFFFFf00000000UL)==0);
				if (rh>0xFFFFFFFFUL) rh=0xFFFFFFFFUL;
				/* search r32 = roundup(mm / bt) bewteen rl..rh */
				while (1) {
					if (rh - rl <= 1) {
						r32 = rh;
						break;
					}
					r32 = (rh + rl) / 2;
					bn_mul32(bt, r32, rt);
					if (bn_cmp(rt, mm) >= 0) rh = r32;
					else rl = r32;
				}
				/* find which one is the quotient of mm/bt, r32 or r32-1 ? */
				bn_mul32(bt, r32, rt);
				if (bn_cmp(mm, rt) < 0) {
					r32--;
					bn_mul32(bt, r32, rt);
				}
				bn_sub(mm, rt, mt);
				/* mt is mm % bt */
				bn_cpy(mt, mm);
				assert(mm[blen] <= bt[blen]);
				/* save the quotient to r */
				bn_lshift32_append(r, r32);
			}
			bn_cpy(r, q);
			/* undo-normalize for the remainder */
			if (nshift) {
				bn_rshift(mm, nshift, mm);
			}
			/* end of undo-normalize */
			bn_cpy(mm, m);

			break;
	}
}

/* HAC 14.20 Algorithm Multiple-precision division */
/* a = q*b + r,    0 <= r < y, an...a1a0, bt...b1b0 */
void  bn_hac_div(bn_t a, bn_t b, bn_t q, bn_t r)
{
	int i, n, t, f, nshift = 0;
	bn_t w, x, y, ys, wz;

	bn_cpy(a, x);
	bn_cpy(b, y);
	switch (bn_cmp(x, y)) {
		case -1:
			bn_clear(q);
			bn_cpy(x, r);
			break;
		case  0:
			bn_setone(q);
			bn_clear(r);
			break;
		case +1:
			/* start of normalization */
			n = bn_getlen(x) - 1;
			nshift = bn_getmsbposn(y) % 32;
			if ((n < BN_LEN - 1) && (nshift != 0)) {
				nshift = 32 - nshift;
				bn_lshift(x, nshift, x);
				bn_lshift(y, nshift, y);
			}
			else nshift = 0;
			/* end of normalization */

			bn_clear(w);
			n = bn_getlen(x) - 1;
			t = bn_getlen(y) - 1;
			bn_lshift(y, (n-t)*32, ys);
			while (bn_cmp(x, ys) >= 0) {
				w[n-t]++;
				bn_sub(x, ys, x);
			}

			for (i=n; i>=t+1; i--) {
				if (x[i] == y[t]) w[i-t-1] = ~0;
				else w[i-t-1] = *(uint64_t *)&x[i-1] / y[t];
				while (1) {
#ifdef USE_UINT128
					typedef __uint128_t  uint128_t;
					uint128_t p128; /* product */
					union {
						uint128_t w128;
						uint64_t w64[2];
					} x128;

					p128 = (uint128_t)w[i-t-1] * *(uint64_t *)&y[t-1];
					x128.w64[0] = *(uint64_t *)&x[i-2];
					x128.w64[1] = x[i];
					if (p128 > x128.w128) w[i-t-1]--;
					else break;
#else
					uint32_t p96[3] = {0,0,0};;
					uint64_t wy;

					*(uint64_t *)p96 = (uint64_t)w[i-t-1] * y[t-1];
					wy = (uint64_t)w[i-t-1] * y[t];
					*(uint64_t *)(p96+1) += wy;
					if (p96[2] > x[i]) w[i-t-1]--;
					else if ((p96[2] == x[i]) && (*(uint64_t *)&p96[0] > *(uint64_t *)&x[i-2]))
						w[i-t-1]--;
					else break;
#endif
				}
				bn_lshift(y, (i-t-1)*32, ys);
				bn_mul32(ys, w[i-t-1], wz);
				f = bn_cmp(x, wz);
				bn_sub(x, wz, x);
				if (f < 0) {
					bn_add(x, ys, x);
					w[i-t-1]--;
				}
			}
			/* undo-normalize for the remainder */
			if (nshift) {
				bn_rshift(x, nshift, x);
			}
			/* end of undo-normalize */
			bn_cpy(w, q);
			bn_cpy(x, r);
			break;
	}
}

/**************** mod api ******************/

void bn_addmod(bn_t a, bn_t b, bn_t n, bn_t r)
{
	bn_t t;

	bn_add(a, b, t);
	if (bn_cmp(n, t) <= 0)
		bn_sub(t, n, t);
	bn_cpy(t, r);
}

void bn_submod(bn_t a, bn_t b, bn_t n, bn_t r)
{
	bn_t t;

	bn_sub(a, b, t);
	if (bn_cmp(a, b) < 0)
		bn_add(t, n, r);
	else
		bn_cpy(t, r);
}

/* m = a mod n */
void bn_mod(bn_t a, bn_t n, bn_t m)
{
	bn_t q;
	bn_div(a, n, q, m);
}

/* m = a * b mod n */
void bn_classic_mulmod(bn_t a, bn_t b, bn_t n, bn_t m)
{
	bn_t r, q;

	bn_mul(a, b, r);
	bn_div(r, n, q, m);
}

/* r = 1/a mod n */
void bn_invmod(bn_t a, bn_t n, bn_t r)
{
	bn_eea(n, a, NULL, r, NULL);
}

/* HAC 14.79 Algorithm Left-to-right binary exponentiation */
/* y = x^e mod n */
void bn_bitwise_expmod(bn_t x, bn_t e, bn_t n, bn_t y)
{
	int i, j;
	bn_t r;

	i = bn_getmsbposn(e) - 1;
	j = i % 32;
	i /= 32;

	bn_cpy(x, r);

	for (j--; i>=0; i--) {
		for (; j>=0; j--) {
			bn_mulmod(r, r, n, r);
			if (e[i] & (1<<j)) {
				bn_mulmod(x, r, n, r);
			}
		}
		j = 31;
	}
	bn_cpy(r, y);
}

/* HAC 14.83 Algorithm Modified left-to-right k-ary exponentiation */
/* y= x^e mod n   k-ary algorithm */
void bn_kary_expmod(bn_t x, bn_t e, bn_t n, bn_t y)
{
	const int k = 4;
	int i, j, l;
	uint32_t u32, u4;
	bn_t r, table[16]; /* 1<<k */

	/* precompute the table of exponents */
	bn_setone(table[0]);
	for (i=1; i<(1<<k); i++)
		bn_mulmod(table[i-1], x, n, table[i]);

	/* find MSnibble not zero */
	i = bn_getlen(e) - 1;
	for (j=7; j>=0; j--) {
		if (e[i] & (0xF<<4*j)) break;
	}

	bn_setone(r);

	for (; i>=0; i--) {
		u32 = e[i];
		for (; j>=0; j--) {
			for (l=0; l<k; l++)
				bn_mulmod(r, r, n, r);

			u4 = u32 >> (4*j) & 0x0F;
			if (u4)
				bn_mulmod(r, table[u4], n, r);
		}
		j = 7;
	}

	bn_cpy(r, y);
}

//=============================================================

/*
 * HAC 14.54 Algorithm Binary gcd algorithm
 * INPUT: two positive integers x and y with x>= y
 * OUTPUT: gcd(x, y)
 */
uint32_t bn_bin_gcd(bn_t x, bn_t y, bn_t gcd)
{
	uint32_t shift;
	bn_t u, v, t;

	bn_cpy(x, u);
	bn_cpy(y, v);
	shift = 0;
	while (bn_iseven(u) && bn_iseven(v)) {
		bn_rshift1(u);
		bn_rshift1(v);
		shift++;
	}
	while (!bn_iszero(u)) {
		while (bn_iseven(u)) bn_rshift1(u);
		while (bn_iseven(v)) bn_rshift1(v);
		if (bn_cmp(u, v) >= 0) {
			bn_sub(u, v, t);
			bn_rshift1(t);
			bn_cpy(t, u);
		}
		else {
			bn_sub(v, u, t);
			bn_rshift1(t);
			bn_cpy(t, v);
		}
	}
	bn_lshift(v, shift, gcd);

	return 0;
}

/* BUGS!!!
 * HAC 14.61 Algorithm Binary extended gcd algorithm
 * INPUT: two positive integers x and y
 * OUTPUT: integers a, b, and g such that ax + by = g, where g = gcd(x, y).
 */
uint32_t bn_bin_extended_gcd(bn_t x, bn_t y, bn_t a, bn_t b, bn_t g)
{
	uint32_t shift = 0;
	bn_t u, v;
	bn_t A, B, C, D, X, Y;

	bn_cpy(x, X);
	bn_cpy(y, Y);
	while (bn_iseven(X) && bn_iseven(Y)) {
		bn_rshift1(X);
		bn_rshift1(Y);
		shift++;
	}
	bn_cpy(X, u);
	bn_cpy(Y, v);
	bn_setone(A);
	bn_clear(B);
	bn_clear(C);
	bn_setone(D);
	do {
		while (bn_iseven(u)) {
			bn_rshift1(u);
			if (bn_iseven(A) && !bn_cmp(A, B)) {
				bn_rshift1(A);
				bn_rshift1(B);
			}
			else {
				bn_add(A, Y, A);
				bn_rshift1(A);
				bn_sub(B, X, B);
				bn_rshift1(B);
			}
		}
		while (bn_iseven(v)) {
			bn_rshift1(v);
			if (bn_iseven(C) && !bn_cmp(C, D)) {
				bn_rshift1(C);
				bn_rshift1(D);
			}
			else {
				bn_add(C, Y, C);
				bn_rshift1(C);
				bn_sub(D, X, D);
				bn_rshift1(D);
			}
		}
		if (bn_cmp(u, v) >= 0) {
			bn_sub(u, v, u);
			bn_sub(A, C, A);
			bn_sub(B, D, B);
			if ((B[BN_LEN-1]&(1<<31)) == 0) {
				bn_add(A, Y, A);
				bn_sub(B, X, B);
			}
		}
		else {
			bn_sub(v, u, v);
			bn_sub(C, A, C);
			bn_sub(D, B, D);
			if ((D[BN_LEN-1]&(1<<31)) == 0) {
				bn_add(C, Y, C);
				bn_sub(D, X, D);
			}
		}
	} while (!bn_iszero(u));
	if (a) bn_cpy(C, a);
	if (b) {
		if (D[BN_LEN-1]&(1<<31))
			bn_add(D, x, b);
		else
			bn_cpy(D, b);
	}
	if (g) bn_lshift(v, shift, g);

	return 0;
}

/*
 * Extended Euclidean Algorithm
 * INPUT: two positive integers a and b
 * OUTPUT: integers a, b, and g. such that ax + by = g, where g = gcd(a, b).
 *         such that: x = -a', y = 1/b mod a, g = 1
 *         which is used in montgomery calculation: -n*n' + r*r^(-1) = 1
 */

uint32_t bn_eea(bn_t a, bn_t b, bn_t x, bn_t y, bn_t g)
{
#if 1
	bn_t A, B, X, Y, x1, x2, y1, y2, q, r;

	if (bn_iszero(b)) {
		bn_cpy(a, g);
		bn_setone(x);
		bn_clear(y);
		return 0;
	}

	bn_cpy(a, A); bn_cpy(b, B);
	bn_setone(x2);   bn_clear(x1);
	bn_clear(y2);    bn_setone(y1);
	while(!bn_iszero(B)) {
		bn_div(A, B, q, r);
		bn_mul(q, x1, X);  bn_sub(x2, X, X);
		bn_mul(q, y1, Y);  bn_sub(y2, Y, Y);
		bn_cpy(B, A);   bn_cpy(r, B);
		bn_cpy(x1, x2); bn_cpy(X, x1);
		bn_cpy(y1, y2); bn_cpy(Y, y1);
	}

	if (g) bn_cpy(A,  g);

	if (x) bn_cpy(x2, x);

	/* y can't bigger than a after mod a. if it is, then y is negative */
	if (y) {
		if (bn_cmp(y2, a) > 0) bn_add(y2, a, y);
		else bn_cpy(y2, y);
	}

	return 0;

#else
	bn_t q, s0, s1, s, t0, t1, t, r0, r1, r;

	bn_cpy(a, r0);
	bn_cpy(b, r1);
	bn_setone(s0);
	bn_clear(s1);
	bn_clear(t0);
	bn_setone(t1);
	while ( bn_div(r0, r1, q, r), !bn_iszero(r) ) {
		bn_mul(q, s1, s); bn_sub(s0, s, s);
		bn_mul(q, t1, t); bn_sub(t0, t, t);
		bn_cpy(r1, r0); bn_cpy(r, r1);
		bn_cpy(s1, s0); bn_cpy(s, s1);
		bn_cpy(t1, t0); bn_cpy(t, t1);
	};
	if (g) bn_cpy(r1, g);
	/* y can't bigger than a after mod a. if it is, then y is negative */
	if (bn_cmp(t1, a) > 0) bn_add(t1, a, t1);
	if (y) bn_cpy(t1, y);

	if (x) {
		bn_cpy(s1, a);
	}
	return 0;
#endif
}

//=============================================================

/*
 * HAC 14.32 Algorithm Montgomery reduction
 * INPUT: integers 
 *        T = (t[2n−1] ... t[1]t[0])b < mR
 *        m = (m[n−1] ... m[1]m[0])b with gcd(m, b) = 1, 
 *            m is odd for RSA, so gcd(m,b)=1 will hold
 *        m' = −m^(−1) mod b
 *        radix b = 2^32
 *        R = b^n is sufficient (but not necessary) for efficient implementation
 * OUTPUT:TR^(−1) mod m
 */
uint32_t bn_mont_redc(bn_t T, bn_t m, /*bn_t R,*/ bn_t mp, bn_t TRm)
{
	uint32_t i, n, ui, ov;
	bn_t A, s;

	bn_cpy(T, A);
	n = bn_getlen(m);
	for (i=0; i<n; i++) {
		ui = mp[0] * A[0];
		ov = bn_mul32(m, ui, s);
		ov += bn_add(A, s, A);
		bn_rshift(A, 32, A);
		//A[BN_LEN-1] += ov;
		A[n-1] = ov;
	}
	if (bn_cmp(A, m) >= 0)
		bn_sub(A, m, TRm);
	else
		bn_cpy(A, TRm);
	return 0;
}

/*
 * HAC 14.36 Algorithm Montgomery multiplication
 * INPUT: integers
 *        m = (m[n−1] ... m[1]m[0])  radix b
 *        x = (x[n−1] ... x[1]x[0])  radix b
 *        y = (y[n−1] ... y[1]y[0])  radix b
 *        with 0 <= x, y < m, R = b^n with gcd(m, b) = 1, and m' = −m^(−1) mod b.
 * OUTPUT: xyR^(−1) mod m
 *
 * Here: b = 2^32
 */
void bn_mont_pro_1(bn_t x, bn_t y, bn_t m, bn_t mp, bn_t product)
{
	uint32_t i, l, ui, u32, carry0;
	uint64_t carry1;
	bn_t A, s, t;

	/* 1 */
	bn_clear(A);
	/* 2 */
	l = bn_getlen(m);
	carry0 = 0;
	for (i=0; i<l; i++) {
		/* 2.1  u=(a0 + xi*y0)m' mod b, mod b mean drop carry */
		//u64 = A[0] + (uint64_t)x[i] * y[0]; /* drop the carry */
		//u64 = bn_mul64(mp, u64, u);
		//ui = u[0];
		u32 = A[0] + x[i] * y[0]; /* drop the carry */
		ui = mp[0] * u32;
		/* 2.2 A=(A + xiy + um)/b, /b means shift right */
		carry1 = bn_mul32(y, x[i], t);
		carry1 += bn_mul32(m, ui, s);
		carry1 += bn_add(A, s, A);
		carry1 += bn_add(A, t, A);
		/* carry1 might over 32-bit after the above statments */
		bn_rshift(A, 32, A);
		carry1 += carry0;
		//A[BN_LEN-1] += carry1;
		A[l-1] += carry1;
		carry0 = carry1 >> 32; /* save high 32 bit to carry0 */
	}
	if (l<=BN_LEN-1) A[l] = carry0;
	/* 3 */
	if (bn_cmp(A, m) >= 0)
		bn_sub(A, m, product);
	else
		bn_cpy(A, product);
}

/*
 * Montgomery multiplication
 *
 * https://colinandmargaret.co.uk/Research/Mont_Mult_2ndEd_v4.pdf
 *
 * m is n bits, temperary variable u is n+2 bits
 * bitwise calculation, no need for gcd
 * INPUT:  same as HAC 14.36
 * OUTPUT: xyR^(−1) mod m, where R=2^k
 *
 * function MonPro(a, b) { n is odd and a, b, n < 2^k }
 * ———————————————————
 * Step 1. u := 0
 * Step 2. for i = 0 to k − 1
 * Step 3. u := u + aib
 * Step 4. u := u + u0n
 * Step 5. u := u/2
 * Step 6. if u ≥ n then return u − n
 *         else return u
 * ———————————————————
 */
void bn_mont_pro_2(bn_t x, bn_t y, bn_t m, bn_t mp, bn_t product)
{
	int i, k;
	uint32_t carry;
	bn_t u;

	(void) mp;
	k =  bn_getmsbposn(m);
	bn_clear(u);
	for (i=0; i<k; i++) {
		if (bn_getbit(x, i))
			carry = bn_add(u, y, u);
		if (bn_getbit(u, 0))
			carry += bn_add(u, m, u);
		/* carry might be 2 bits */
		bn_rshift1(u);
		//u[BN_LEN - 1] |= ((carry&1) << 31); /* safe to drop b1 ? */
		if (carry&1) bn_setbit(x, k-1);
	}
	if (carry&2 && k<BN_LEN*32) bn_setbit(x, k);

	if (bn_cmp(u, m) >= 0)
		bn_sub(u, m, product);
	else
		bn_cpy(u, product);
}

/*
 * same as bn_mont_mul_1, this is word-wise.
 * the word size choosen is 4-bit
 * gcd for 32-bit value is easy and fast
 * or the gcd(n, R) can be precomputed and do look-up later
 *
 * https://colinandmargaret.co.uk/Research/Mont_Mult_2ndEd_v4.pdf
 *
 * function MonPro(a, b) { n is odd and a, b, n < 2^(sw) }
 * ———————————————————
 * Step 1. u := 0
 * Step 2. for i = 0 to s − 1
 * Step 3. u := u + aib
 * Step 4. u := u + (−n0^(-1))) · u0 · n
 * Step 5. u := u/2^w
 * Step 6. if u ≥ n then return u − n
 *         else return u
 * ———————————————————
 */
void bn_mont_pro_3(bn_t x, bn_t y, bn_t m, bn_t mp, bn_t product)
{
	int i, s;
	uint64_t nu;
	bn_t R, u;

	s = bn_getlen(m);
	bn_clear(u);
	for (i=0; i<s; i++) {
		bn_mul32(y, x[i], R);
		bn_add(u, R, u);
		nu = mp[0] * u[0];
		bn_qw2bn(nu, R);
		bn_mul(m, R, R);
		bn_add(u, R, u);
		bn_rshift(u, 32, u);
	}
	if (bn_cmp(u, m) >= 0)
		bn_sub(u, m, product);
	else
		bn_cpy(u, product);
}

/* a = a * r mod n; which r is one more bit than m */
static void bn_axr_mod_n(bn_t a, bn_t n, bn_t b)
{
	int i, bits;
	bn_t xa;

	bn_cpy(a, xa);
	while (bn_cmp(xa, n) >= 0)
		bn_sub(xa, n, xa);

	bits = bn_getlen(n) * 32;
	for (i=0; i<bits; i++) {
		bn_lshift1(xa);
		if (bn_cmp(xa, n)>=0)
			bn_sub(xa, n, xa);
	}
	bn_cpy(xa, b);
}

void bn_mont_mulmod(bn_t a, bn_t b, bn_t n, bn_t product)
{
	bn_t np;

	bn_get_n_prime(n, np);
	bn_mont_mulmod_with_np(a, b, n, np, product);
}

/*
 * product = a * b mod n
 *
 * n is odd number
 * r*r^(-1) - n*n' = 1
 *     np is n' in the function
 *
 * The integers r^(−1) and n' can both be computed by the 
 * Extended Euclidean Algorithm
 */
#if 1
/* better implementation */
void bn_mont_mulmod_with_np(bn_t a, bn_t b, bn_t n, bn_t np, bn_t product)
{
	bn_t xa;

	/*         _
	 * compute a = a * r mod n
	 */
	bn_axr_mod_n(a, n, xa);
	bn_mont_pro(xa, b, n, np, product);
}
#else
void bn_mont_mulmod_with_np(bn_t a, bn_t b, bn_t n, bn_t np, bn_t product)
{
	bn_t one, xa, xb;

	bn_setone(one);
	bn_axr_mod_m(a, n, xa);
	bn_axr_mod_m(b, n, xb);
	bn_mont_pro(xa, xb, n, np, product);
	bn_mont_pro(product, one, n, np, product);
}
#endif

/* R mod n */
static void r_mod_n(bn_t r, bn_t n, bn_t r_n)
{
	bn_sub(r, n, r_n);
	while (bn_cmp(r_n, n) >= 0)
		bn_sub(r_n, n, r_n);
}

void bn_get_n_prime(bn_t n, bn_t np)
{
	bn_t R, m;

	bn_clear(R);
	if (bn_mont_pro == bn_mont_pro_1) {
		R[bn_getlen(n)] = 1;
		bn_cpy(n, m);
		/* R has half of BN_LEN for RSA signature creation and decryption */
	}
	else if (bn_mont_pro == bn_mont_pro_3) {
		bn_qw2bn(1UL<<32, R);
		bn_clear(m); m[0] = n[0];
	}

	if (bn_mont_pro != bn_mont_pro_2) {
		bn_eea(m, R, np, NULL, NULL);

		if (np[BN_LEN-1] & 1<<31) bn_clear(R);
		bn_sub(R, np, np);
	}
}

/*
 * HAC 14.94 Algorithm Montgomery exponentiation
 * y = x^e mod n
 */
void bn_mont_expmod(bn_t x, bn_t e, bn_t n, bn_t y)
{
	int i, t;
	bn_t one, R, A, np, xt, r_n, r2_n;

	bn_get_n_prime(n, np);

	bn_clear(R); R[bn_getlen(n)] = 1;

	/* calculate r_n = R mod n */
	r_mod_n(R, n, r_n);
	/*
	 * calculate r2_n = R^2 mod n
	 * A*B mod N = ((A mod N) * (B mod N)) mod N
	 */
	bn_mont_mulmod_with_np(r_n, r_n, n, np, r2_n);

	/* 1 */
	bn_mont_pro(x, r2_n, n, np, xt);
	bn_cpy(r_n, A);
	t = bn_getmsbposn(e) - 1;
	/* 2 */
	for (i=t; i>=0; i--) {
		/* 2.1 */
		bn_mont_pro(A, A, n, np, A);
		/* 2.2 */
		if (bn_getbit(e, i)) {
			bn_mont_pro(A, xt, n, np, A);
		}
	}
	/* 3 */
	bn_setone(one);
	bn_mont_pro(A, one, n, np, y);
}

//=============================================================

