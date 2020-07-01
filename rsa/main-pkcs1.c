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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsaes-pkcs1.h"

int main(int argc, char *argv[])
{
	const int keybits = 1024;
	const int nbytes = (keybits+7) / 8;
	int nbits = keybits;
	int rc = 0;
	rsaes_pkcs1_ctx_t ctx;
	uint8_t msg_in[] = {"\xd4\x36\xe9\x95\x69\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49"};
	uint8_t em[nbytes];
	uint8_t out[nbytes];
	int out_len;
	int msg_len = strlen(msg_in);

	rc |= rsaes_pkcs1_init(&ctx, nbits, (enum hash_id)0);
	rc |= ctx.encodepad(&ctx, msg_len, msg_in, em);
        rc |= ctx.decodepad(&ctx, nbytes, em, &out_len, out);
	if (rc || out_len!=msg_len || memcmp(msg_in, out, msg_len))
		printf("RSAES-PKCS1 V1.5 TEST FAILED\n");
	else
		printf("RSAES-PKCS1 V1.5 TEST PASSED\n");
	return rc;
}

