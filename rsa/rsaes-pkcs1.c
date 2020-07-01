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

#include <stdlib.h>
#include <string.h>
#include "random.h"
#include "rsa.h"
#include "rsaes-pkcs1.h"

/*
 * According to Section 7.2 of "PKCS #1 v2.2: RSA Cryptography Standard"
 * As a general rule, the use of this scheme(RSAES-PKCS1-v1_5) for encrypting an
 * arbitrary message, as opposed to a randomly generated key, is not recommended.
 *
 * In any case, the RSAES-OAEP scheme overcomes the attack.
 */
static int rsaes_pkcs1_encodepad(rsaes_pkcs1_ctx_t *ctx, size_t msglen, uint8_t *msg, uint8_t *em);
static int rsaes_pkcs1_decodepad(rsaes_pkcs1_ctx_t *ctx, int emlen, uint8_t *em, int *outlen, uint8_t *out);


int rsaes_pkcs1_init(rsaes_pkcs1_ctx_t *ctx, int rsa_nbits, enum hash_id hash_id)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->init      = rsaes_pkcs1_init;
	ctx->encodepad = rsaes_pkcs1_encodepad;
	ctx->decodepad = rsaes_pkcs1_decodepad;

	ctx->k = (rsa_nbits + 7)/ 8;

	/* no hash is used in the scheme */

	return 0;
}

static int rsaes_pkcs1_encodepad(rsaes_pkcs1_ctx_t *ctx, size_t msglen, uint8_t *msg, uint8_t *em)
{
	memset(em, 0xAA, ctx->k);
	if (msglen > ctx->k - 11) return -1;
	em[0] = 0;
	em[1] = 2;
	if (get_random((ctx->k-msglen-3)*8, &em[2]) != (ctx->k-msglen-3)*8) return -2;
	em[ctx->k-msglen-1] = 0;
	memcpy(&em[ctx->k-msglen], msg, msglen);
	return 0;
}

static int rsaes_pkcs1_decodepad(rsaes_pkcs1_ctx_t *ctx, int emlen, uint8_t *em, int *outlen, uint8_t *out)
{
	uint8_t *p;
	if (emlen != ctx->k || ctx->k < 11) return -3;
	if (em[0]) return -1;
	if (em[1] != 2)  return -2;
	p = memchr(&em[2], 0, ctx->k-2);
	if (!p) return -3;
	*outlen = ctx->k - (++p - em);
	memcpy(out, p, *outlen);
	return 0;
}

