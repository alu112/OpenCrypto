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

/* HAC 4.24 Miller-Rabin Probabilistic Primality Test
 *
 * MILLER-RABIN(n,t)
 * INPUT: an odd integer n > 2 and security parameter t > 0.
 * OUTPUT: an answer "prime" or "composite" to the question: "Is n prime?"
 * 1. Write n − 1 = (2^s)*r such that r is odd.
 * 2. For i from 1 to t do the following:
 *    2.1 Choose a random integer a, 2 <= a <= n − 2.
 *    2.2 Compute y = a^r mod n using Algorithm 2.143.
 *    2.3 If y 6 = 1 and y 6 = n − 1 then do the following:
 *        j=1.
 *        While j <= s − 1 and y <> n − 1 do the following:
 *            Compute y = y^2 mod n.
 *            If y = 1 then return("composite").
 *            j = j + 1.
 *        If y <> n − 1 then return ("composite").
 * 3. Return("prime").
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "random.h"
#include "bn.h"


#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif


static /*const*/ uint16_t primes[] = {
   2,    3,    5,    7,   11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,   53, 
  59,   61,   67,   71,   73,   79,   83,   89,   97,  101,  103,  107,  109,  113,  127,  131, 
 137,  139,  149,  151,  157,  163,  167,  173,  179,  181,  191,  193,  197,  199,  211,  223, 
 227,  229,  233,  239,  241,  251,  257,  263,  269,  271,  277,  281,  283,  293,  307,  311, 
 313,  317,  331,  337,  347,  349,  353,  359,  367,  373,  379,  383,  389,  397,  401,  409, 
 419,  421,  431,  433,  439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,  503, 
 509,  521,  523,  541,  547,  557,  563,  569,  571,  577,  587,  593,  599,  601,  607,  613, 
 617,  619,  631,  641,  643,  647,  653,  659,  661,  673,  677,  683,  691,  701,  709,  719, 
#if 0
 727,  733,  739,  743,  751,  757,  761,  769,  773,  787,  797,  809,  811,  821,  823,  827, 
 829,  839,  853,  857,  859,  863,  877,  881,  883,  887,  907,  911,  919,  929,  937,  941, 
 947,  953,  967,  971,  977,  983,  991,  997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 
1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 
1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 
1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 
1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 
1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 
#endif
};

#if 0
void prime_table(void)
{
	int i, j, k;

	if (primes[0] == 2) return;
	primes[0] = 2;
	for (j=0,i=3; j<ARRAY_SIZE(primes); i++) {
		for (k=0; k<=j; k++) {
			if (i%primes[k] == 0) break;
			if (k==j) primes[++j] = i;
		}
	}
	for (i=0;i<j;i+=16) {
		for (k=0;k<16;k++) {
			if (i+k<j)
				printf("%4d, ", primes[i+k]);
		}
		printf("\n");
	}
}
#endif

bool is_primesmall(bn_t n)
{
	int i;
	uint32_t r;
	bn_t q;

	for (i=0; i<ARRAY_SIZE(primes); i++) {
		bn_divu32(n, primes[i], q, &r);
		if (!r)
			return false;
	}
	return true;
}

/* convert n-1 = (2^s)r */
static void decompose(bn_t n1, uint32_t *s, bn_t r)
{
	uint32_t u;
	bn_t x;

	u = 0;
	bn_cpy(n1, x);
	while(bn_iseven(x)) {
		u++;
		bn_rshift1(x);
	}

	bn_cpy(x, r);
	*s = u;
}

/* HAC 4.24 Algorithm Miller-Rabin probabilistic primality test */
/* don't call this function if n<=primes[ARRAY_SIZE-1], search the primes[] instead */
bool is_prime(bn_t n, int t)
{
	bool composite;
	uint32_t j, s;
	bn_t one, n1, a, r, y;

	/* even number are not prime */
	if (bn_iseven(n)) return false;

	bn_setone(one);
	bn_cpy(n, n1);
	bn_subx(1, n1); /* n1 = n - 1 */

	decompose(n1, &s, r);

	for (; t; t--) {
		printf("-"); fflush(stdout);
		bn_gen_random(10, a);

		bn_expmod(a, r, n, y); /* y = a^r mod n */

		composite = bn_cmp(y, n1);
		if (bn_cmp(y, one) && composite) {
			for (j=1; j<s && composite; j++) {
				bn_mulmod(y, y, n, y);
				if (!bn_cmp(y, one))
					return false;
				composite = bn_cmp(y, n1);
			}
			if (composite)
				return false;
		}
	}
	return true;
}

/*
 * HAC 4.44 Algorithm Random search for a prime using the Miller-Rabin test
 * The proportion of all odd integers <= 2^2048 that are prime is 
 * approximately 2/(2048*ln(2)) ≈ 1/1419
 */
int get_prime(int k, int t, bn_t p)
{
	bn_gen_random(k, p);
	do {
		bn_addx(2, p);
		while (!is_primesmall(p)) {
			bn_addx(2, p);
		}
		printf("."); fflush(stdout);
	} while (!is_prime(p, t));
	printf("#\n");

	return 0;
}

/* 4.62 Algorithm Maurer’s algorithm for generating provable primes */
int get_provable_prime(int k, bn_t p)
{
	return 0;
}

