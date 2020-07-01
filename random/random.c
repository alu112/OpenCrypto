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

#include "bn.h"
#include "random.h"

#ifndef USE_LINUX_URANDOM

#include <string.h>
#include <sys/time.h>
#include "sha-common.h"
#include "sha1.h"

/* 20 bytes pseudorandom output */
static int rand(uint8_t rnd20[SHA1_DIGEST_LENGTH/8])
{
	int i, again;
	sha_ctx_t ctx;
	struct timeval tv;
	uint8_t t[SHA1_DIGEST_LENGTH/8];
	/* don't initialize c[], just use the value AS IS */
	uint8_t c[SHA1_DIGEST_LENGTH/8];

	if (gettimeofday(&tv, NULL)) return -1;
	if (hash_init(eHASH_SHA1, &ctx)) return -2;
	ctx.update(&ctx, (uint8_t *)&tv, sizeof(tv));
	ctx.final(&ctx, t);
	do {
		/* HAC Algorithm 5.15 */
		ctx.init(&ctx);
		memcpy(((sha1_ctx_t *)&ctx)->state, t, sizeof(t));
		ctx.update(&ctx, c, sizeof(c));
		ctx.final(&ctx, rnd20);
		/* end of HAC Algorithm 5.15 */
		again = 0;
		for (i=0; i<SHA1_DIGEST_LENGTH/8; i++) {
			if (!rnd20[i]) again = 1;
		}
		if (again) memcpy(c, rnd20, SHA1_DIGEST_LENGTH/8);
	} while (again);

	return 0;
}

/* if array u8[] is longer than nbits, the caller have to clear it first */
int  get_random(int nbits, uint8_t u8[])
{
	int n = nbits;
	uint8_t rnd[SHA1_DIGEST_LENGTH/8];
	for (; n>=0; n-=SHA1_DIGEST_LENGTH) {
		if (rand(rnd)) return -1;
		if (n > SHA1_DIGEST_LENGTH)
			memcpy(u8+(n-SHA1_DIGEST_LENGTH)/8, rnd, SHA1_DIGEST_LENGTH/8);
		else
			memcpy(u8, rnd, (n+7)/8);
	}
	/* make sure msbit = 1 */
	u8[0] &= (0xFF >> ((8-nbits%8)&7));
	u8[0] |= (1<<(nbits-1)%8);
	/* make sure lsbit = 1 */
	u8[(nbits+7)/8-1] |= 1;
	return nbits;
}

#else

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* if array u8[] is longer than nbits, the caller have to clear it first */
int  get_random(int nbits, uint8_t u8[])
{
	int fd, nbytes;

	nbytes = (nbits+7)/8;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd) {
		while (nbytes) {
			read(fd, &u8[nbytes-1], 1);
			if (u8[nbytes-1]) nbytes--;
		}
		close(fd);
		/* make sure msbit = 1 */
		u8[0] &= ((0xFF >> (8-nbits%8))&7);
		u8[0] |= (1<<(nbits-1)%8);
		/* make sure lsbit = 1 */
		u8[(nbits+7)/8-1] |= 1;
		return nbits;
	}
	return -1;
}

#endif

uint32_t bn_gen_random(int bitlength, bn_t bn)
{
        uint8_t c;
        int i, n = (bitlength+7)/8;
        uint8_t *p8 = (uint8_t *)bn;

	bn_clear(bn);
        if (get_random(bitlength, p8)<0) return -1;
        for (i=0; i<n/2; i++) {
                c = p8[i];
                p8[i] = p8[n-i-1];
                p8[n-i-1] = c;
        }
        return bitlength;
}

