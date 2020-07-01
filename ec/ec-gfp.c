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
#include "random.h"
#include "gfp.h"
#include "ec-gfp.h"
#include "ec-param.h"


/* generate private/public key pair from the specific curve */
int ec_keygen_gfp(char *name, ec_keyblob_t * keys)
{
	int len;
	len = ec_getcurve(name, &keys->ec);
	if (len > 0) {
		bn_gen_random(keys->ec.keylen, keys->private);
		gfp_mulmod(&keys->ec.g, keys->private, &keys->ec, &keys->public);
	}
	return len;
}

/* calculate the secret from my prvkey and peer's public key */
void ecdh_gfp(ec_keyblob_t *mykey, gfp_point_t *peer_pub, gfp_point_t *my_secret)
{
	gfp_mulmod(peer_pub, mykey->private, &mykey->ec, my_secret);
}

#ifdef EC_TESTVECT
	bn_t ectest_k;
#endif
/* RFC6090 5.4.2  KT-I Signature Creation */
void ecdsa_sign_gfp(ec_keyblob_t *key, uint8_t *hash, uint32_t hlen, gfp_point_t *signature)
{
	gfp_point_t pnt;
	bn_t k, invk, z, rd, dgst;
	int rlen, shift;

	bn_ba2bn(hash, hlen, dgst);

	rlen = bn_getmsbposn(key->ec.order);
	shift = hlen*8 - rlen;
	if (shift > 0) {
		//printf("reduce HASH\n");
		bn_rshift(dgst, shift, dgst);
	}

	do {
		bn_gen_random(key->ec.keylen, k);
#ifdef EC_TESTVECT
		bn_cpy(ectest_k, k);
#endif
		bn_mod(k, key->ec.order, k);
		gfp_mulmod(&key->ec.g, k, &key->ec, &pnt);
		bn_mod(pnt.x, key->ec.order, pnt.x);
		bn_invmod(k, key->ec.order, invk);
		bn_clear(k);
		bn_mulmod(key->private, pnt.x, key->ec.order, rd);
		bn_addmod(dgst, rd, key->ec.order, z);
		bn_mulmod(invk, z, key->ec.order, signature->y);
		bn_clear(invk);
		bn_cpy(pnt.x, signature->x);
	} while (bn_iszero(signature->x) || bn_iszero(signature->y));
}

/* RFC6090 5.4.3 Signature Verification */
bool ecdsa_verify_gfp(ec_keyblob_t *key, gfp_point_t *peer_pub, uint8_t *hash, uint32_t hlen, gfp_point_t *signature)
{
	gfp_point_t ug, vp, xy;
	bn_t z, invs, u, v, dgst;
        int rlen, shift;

        bn_ba2bn(hash, hlen, dgst);

        rlen = bn_getmsbposn(key->ec.order);
        shift = hlen*8 - rlen;
        if (shift > 0) {
                //printf("reduce HASH\n");
                bn_rshift(dgst, shift, dgst);
        }

	bn_invmod(signature->y, key->ec.order, invs);
	bn_mulmod(invs, dgst, key->ec.order, u);
	bn_mulmod(invs, signature->x, key->ec.order, v);
	gfp_mulmod(&key->ec.g, u, &key->ec, &ug);
	gfp_mulmod(peer_pub, v, &key->ec, &vp);
	if (gfp_isequal(&ug, &vp))
		gfp_dblmod(&ug, &key->ec, &xy);
	else
		gfp_addmod(&ug, &vp, &key->ec, &xy);

	bn_mod(xy.x, key->ec.order, z);

	return !bn_cmp(z, signature->x);
}

