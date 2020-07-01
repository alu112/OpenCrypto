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

#ifndef __PRIMALITY_H__
#define __PRIMALITY_H__

#include "bn.h"

/* HAC 4.24 Algorithm Miller-Rabin probabilistic primality test */
/* don't call this function if n<=primes[ARRAY_SIZE-1], search the primes[] instead */
bool is_prime(bn_t n, int k);

/* HAC 4.44 Algorithm Random search for a prime using the Miller-Rabin test */
int get_prime(int k, int t, bn_t p);

#endif /* __PRIMALITY_H__ */

