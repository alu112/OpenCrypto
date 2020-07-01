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
#include <stdlib.h>
#include <stdio.h>
#include "sha1.h"

/*
 * echo -n 'A' > f.txt
 * openssl dgst -sha1 f.txt
 */

#define DGST_BYTES (SHA1_DIGEST_LENGTH/8) /* it is ctx.md_len / 8 */

int main(int argc, char *argv[])
{
	int i;
	sha1_ctx_t ctx;
	uint8_t vect1[] = {""};
	uint8_t vect2[] = {"abc"};
	uint8_t vect3[] = {"qwertyuiopasdfghjklzxcvbnmdfghjjhfsweryggfffffqsgsgrkart"};
	uint8_t vect4a[] = {"reuowroeruouirdfnfdjfdjdfljkfflkdjfljkfjsdjldfjlfdjf"};
	uint8_t vect4b[] = {"thisisatestvectorfortestvectorfourbwhichisanactualsentencedf"};
	uint8_t vect5[1000000];
	uint8_t vect6[] = {"testdksllkasdlakldlkjkdlluerymnbmvxeuwqtgfdjgfuopghdjscvxcvsgdah"};

	uint8_t dgst1[DGST_BYTES];
	uint8_t dgst2[DGST_BYTES];
	uint8_t dgst3[DGST_BYTES];
	uint8_t dgst4[DGST_BYTES];
	uint8_t dgst5[DGST_BYTES];
	uint8_t dgst6[DGST_BYTES];
	uint8_t digest[DGST_BYTES];

	memset(vect5, 'a', sizeof(vect5));
	sha1_init(&ctx); /* it only needs to call once */

	ctx.update(&ctx, vect1, 0);
	ctx.final(&ctx, digest);
	memcpy(dgst1, digest, DGST_BYTES);
	assert(!memcmp(digest, dgst1, DGST_BYTES));

	ctx.update(&ctx, vect2, strlen(vect2));
	ctx.final(&ctx, digest);
	memcpy(dgst2, digest, DGST_BYTES);
	assert(!memcmp(digest, dgst2, DGST_BYTES));

	ctx.update(&ctx, vect3, strlen(vect3));
	ctx.final(&ctx, digest);
	memcpy(dgst3, digest, DGST_BYTES);
	assert(!memcmp(digest, dgst3, DGST_BYTES));

	ctx.update(&ctx, vect4a, strlen(vect4a));
	ctx.update(&ctx, vect4b, strlen(vect4b));
	ctx.final(&ctx, digest);
	memcpy(dgst4, digest, DGST_BYTES);
	assert(!memcmp(digest, dgst4, DGST_BYTES));

	ctx.update(&ctx, vect5, sizeof(vect5));
	ctx.final(&ctx, digest);
	memcpy(dgst5, digest, DGST_BYTES);
	assert(!memcmp(digest, dgst5, DGST_BYTES));

	for (i=0; i<16777216; i++)
		ctx.update(&ctx, vect6, strlen(vect6));
	ctx.final(&ctx, digest);
	memcpy(dgst6, digest, DGST_BYTES);
	assert(!memcmp(digest, dgst6, DGST_BYTES));

	printf("ALL TESTS PASSED!\n");
	return 0;
}

