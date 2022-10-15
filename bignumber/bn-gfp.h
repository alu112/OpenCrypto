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

#ifndef __BN_GFP_H__
#define __BN_GFP_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifndef MAXBITLEN  /* RSA Private Key Length */
#define MAXBITLEN  2048 /* multiple of 32-bit */
#endif

//#define BN_LEN  ((MAXBITLEN / 32 + 1) * 2)
//#define BN_LEN  (((MAXBITLEN + 31) / 32) * 2) /* Good for bitwise_expmod() kary_expmod() */
//#define BN_LEN  (((MAXBITLEN + 31) / 32) * 2+4)
#define BN_LEN  (((MAXBITLEN + 31) / 32) * 2 + 2)
/*
 * bn_t array structure:
 *
 * Idx: 0           1       ......    BN_LEN-1
 * +----------+----------+----------+----------+
 * |  LSDW    |          |  ......  |   MSDW   |
 * +----------+----------+----------+----------+
 */
typedef uint32_t bn_t[BN_LEN];

void bn_print(char * msg, bn_t a);
/* print n bytes */
void bn_print_len(char *msg, bn_t bn, int n);
void bn_swap(bn_t a, bn_t b);
int  bn_getbit(bn_t a, int i);
void bn_setbit(bn_t a, int i);
void bn_clrbit(bn_t a, int i);
/* get how many uint32 units */
int bn_getlen(bn_t bn);
/* get msbit position */
int bn_getmsbposn(bn_t bn);
/* bn = 0 */
void bn_clear(bn_t bn);
/* bn = 1 */
void bn_setone(bn_t bn);
/* set bn = uint64 */
void bn_qw2bn(uint64_t u64, bn_t b);
/* set bn to the hexstring */
void bn_hex2bn(uint8_t *str, bn_t r);
void bn_bn2hex(bn_t a, uint8_t *hex);
/* copy bytes array to bn */
void bn_ba2bn(uint8_t *bytes, int len, bn_t r);
void bn_bn2ba(bn_t r, int len, uint8_t *bytes);
bool bn_iszero(bn_t bn);
bool bn_isone(bn_t bn);
bool bn_isodd(bn_t bn);
bool bn_iseven(bn_t bn);
/* no negative number */
bool bn_ispositive(bn_t bn);
/* to = from */
void bn_cpy(bn_t from, bn_t to);
/* copy [from] n uint32 start from offset to [to] */
void bn_cpylen(int offset, int n, bn_t from, bn_t to);
/* b = a << nbits */
void bn_lshift(bn_t a, int nbits, bn_t b);
/* b = a >> nbits */
void bn_rshift(bn_t a, int nbits, bn_t b);
/* bn <<= 32 */
void bn_lshift32(bn_t bn);
/* bn = bn<<32 | u32 */
void bn_lshift32_append(bn_t bn, uint32_t u32);
/* bn <<= 1 , which is bn*2 */
void bn_lshift1(bn_t bn);
/* bn >>= 1 , which is bn/2 */
void bn_rshift1(bn_t bn);
/* a = a + uint32 */
uint32_t bn_addx(uint32_t x, bn_t a);
/* a = a - uint32 */
uint32_t bn_subx(uint32_t x, bn_t a);
/* r = a + b */
uint32_t bn_add(bn_t a, bn_t b, bn_t r);
/* r = a - b */
uint32_t bn_sub(bn_t a, bn_t b, bn_t r);
/*
 * return 1: a > b
 *        0: a == b
 *       -1: a < b
 */
int  bn_cmp(bn_t a, bn_t b);
/* r = a * u32 */
uint32_t bn_mult32(bn_t a, uint32_t u32, bn_t r);
/* r = a * u64 */
uint64_t bn_mult64(bn_t a, uint32_t u64, bn_t r);
/* r = a * b */
uint32_t bn_mul(bn_t a, bn_t b, bn_t r);
/* HAC 14.16 Algorithm Multiple-precision squaring */
uint32_t bn_sqr(bn_t x, bn_t y);
/* q = a / s;  r = a % s */
void bn_divu32(bn_t a, uint32_t s, bn_t q, uint32_t *r);
/*
 * q = a / b;  m = a % b
 * if q and m point to same location
 * then m contain correct value, q is overwritten by m
 */
void bn_classic_div(bn_t a, bn_t b, bn_t q, bn_t m);
/* HAC 14.20 Algorithm Multiple-precision division */
/* a = q*b + r,    0 <= r < y, an...a1a0, bt...b1b0 */
void bn_hac_div(bn_t a, bn_t b, bn_t q, bn_t r);

/* global function pointers, to select various algorithms */
extern void (*bn_div)(bn_t, bn_t, bn_t, bn_t);

/************ mod APIs **************/
/* r = a + b mod n */
void bn_addmod(bn_t a, bn_t b, bn_t n, bn_t r);
/* r = a - b mod n */
void bn_submod(bn_t a, bn_t b, bn_t n, bn_t r);
/* m = a % n */
void bn_mod(bn_t a, bn_t n, bn_t m);
/* r = 1/a mod n */
void bn_invmod(bn_t a, bn_t n, bn_t r);
/* r = a * b mod n */
void bn_classic_mulmod(bn_t a, bn_t b, bn_t n, bn_t r);
void bn_mont_mulmod(bn_t a, bn_t b, bn_t n, bn_t r);
void bn_mont_mulmod_with_np(bn_t a, bn_t b, bn_t n, bn_t np, bn_t r);

/* global function pointers, to select various algorithms */
extern void (*bn_mulmod)(bn_t a, bn_t b, bn_t n, bn_t r);

/*
 * HAC 14.54 Algorithm Binary gcd algorithm
 * INPUT: two positive integers x and y with x>= y
 * OUTPUT: gcd(x, y)
 */
uint32_t bn_bin_gcd(bn_t x, bn_t y, bn_t gcd);
/*  BUGS!!!
 * HAC 14.61 Algorithm Binary extended gcd algorithm
 * INPUT: two positive integers x and y
 * OUTPUT: integers a, b, and g such that ax + by = g, where g = gcd(x, y).
 */
uint32_t bn_bin_extended_gcd(bn_t x, bn_t y, bn_t a, bn_t b, bn_t g);
/*
 * Extended Euclidean Algorithm
 * INPUT: two positive integers a and b
 * OUTPUT: integers a, b, and g. such that ax + by = g, where g = gcd(a, b).
 *         such that: x = -a', y = 1/b mod a, g = 1
 *         which is used in montgomery calculation: -n*n' + r*r^(-1) = 1
 */
uint32_t bn_eea(bn_t a, bn_t b, bn_t x, bn_t y, bn_t g);


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
uint32_t bn_mont_redc(bn_t T, bn_t m, /*bn_t R,*/ bn_t mp, bn_t TRm);

void bn_get_n_prime(bn_t n, bn_t np);
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
void bn_mont_pro_1(bn_t x, bn_t y, bn_t m, bn_t mp, bn_t product);
void bn_mont_pro_2(bn_t x, bn_t y, bn_t m, bn_t mp, bn_t product);
void bn_mont_pro_3(bn_t x, bn_t y, bn_t m, bn_t mp, bn_t product);
extern void (*bn_mont_pro)(bn_t , bn_t , bn_t , bn_t , bn_t );
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
void bn_mont_mulmod_with_np(bn_t a, bn_t b, bn_t n, bn_t np, bn_t product);
/*
 * HAC 14.94 Algorithm Montgomery exponentiation
 * y = x^e mod m
 */
void bn_mont_expmod(bn_t x, bn_t e, bn_t n, bn_t y);
/* HAC 14.79 Algorithm Left-to-right binary exponentiation */
/* y = x^e mod n */
void bn_bitwise_expmod(bn_t x, bn_t e, bn_t n, bn_t y);
/* HAC 14.83 Algorithm Modified left-to-right k-ary exponentiation */
/* y= x^e mod n   k-ary algorithm */
void bn_kary_expmod(bn_t a, bn_t e, bn_t n, bn_t m);

/* global function pointers, to select various algorithms */
extern void (*bn_expmod)(bn_t, bn_t, bn_t, bn_t);

#endif /* __BN_GFP_H__ */

