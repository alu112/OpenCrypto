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
#include <stdio.h>
#include "random.h"
#include "gf2m.h"
#include "ec-gf2m.h"
#include "ec-param.h"

/* generate private/public key pair from the specific curve */
int ec_keygen_gf2m(char *name, ec_keyblob_t * keys)
{
	int res;
	res = ec_getcurve(name, &keys->ec);
	if (res > 0) {
		bn_gen_random(keys->ec.keylen, keys->private);
		gf2m_mulmod(&keys->ec.g, keys->private, &keys->ec, &keys->public);
	}
	return res;
}

/* calculate the secret from my prvkey and peer's public key */
void ecdh_gf2m(ec_keyblob_t *mykey, gfp_point_t *peer_pub, gfp_point_t *my_secret)
{
	gf2m_mulmod(peer_pub, mykey->private, &mykey->ec, my_secret);
}

/* RFC6090 5.4.2  KT-I Signature Creation */
/*
 * https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
 *
 * G	elliptic curve base point, a point on the curve that generates a subgroup of large prime order n
 * n	integer order of G, means that nG=O, where O is the identity element.
 * d	the private key (randomly selected)
 * Q	the public key (calculated by elliptic curve)
 * m	the message to send
 *
 * 1. Calculate e=HASH(m)
 * 2. Let z be the Ln leftmost bits of e, where Ln is the bit length of the group order
 *      (Note that z can be greater than n but not longer)
 * 3. Select a cryptographically secure random integer k from [1,n-1]
 * 4. Calculate the curve point (x1,y1)=kG
 * 5. Calculate r=x1 mod n. If r==0, go back to step 3.
 * 6. Calculate s=k^(-1)(z+rd) mod n. If s==0, go back to step 3.
 * 7. The signature is the pair (r,s). (And (r,-s) mod n is also a valid signature.)
 *
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf
 *
 */
#ifdef EC_TESTVECT
	bn_t ectest_k;
#endif
void ecdsa_sign_gf2m(ec_keyblob_t *key, uint8_t *hash, uint32_t hlen, gfp_point_t *signature)
{
	gfp_point_t pnt;
	bn_t k, invk, z, rd, dgst;
	int rlen, shift;

	bn_ba2bn(hash, hlen, dgst);

	rlen = bn_getmsbposn(key->ec.order);
	shift = hlen*8 - rlen;
	if (shift > 0) {
		printf("reduce HASH\n");
		bn_rshift(dgst, shift, dgst);
	}

	do {
		bn_gen_random(rlen, k);
#ifdef EC_TESTVECT
		printf("copy test k\n");
		bn_cpy(ectest_k, k);
#endif
		bn_mod(k, key->ec.order, k);
		gf2m_mulmod(&key->ec.g, k, &key->ec, &pnt);
		bn_mod(pnt.x, key->ec.order, pnt.x);

		bn_invmod(k, key->ec.order, invk);
		bn_clear(k);
		bn_mulmod(key->private, pnt.x, key->ec.order, rd);
		bn_addmod(dgst, rd, key->ec.order, z);
		bn_mulmod(invk, z, key->ec.order, signature->y);
		bn_clear(invk);
		bn_cpy(pnt.x, signature->x);
	} while(bn_iszero(signature->x) || bn_iszero(signature->y)); 
}

/* RFC6090 5.4.3 Signature Verification */
/*
 * Check that Q is not equal to the identity element O, and its coordinates are otherwise valid
 * Check that Q lies on the curve
 * Check that nQ=O
 *
 * After that, Bob follows these steps:
 *
 * Verify that r and s are integers in [1,n-1]. If not, the signature is invalid.
 * Calculate e=HASH(m), where HASH is the same function used in the signature generation.
 * Let z be the Ln leftmost bits of e
 * Calculate u=zs^(-1) mod n and v=rs^(-1) mod n
 * Calculate the curve point (x,y)=uG+vQ. If (x,y)=O then the signature is invalid.
 * The signature is valid if r == x mod n, invalid otherwise.
 *
 */

bool ecdsa_verify_gf2m(ec_keyblob_t *key, gfp_point_t *peer_pub, uint8_t *hash, uint32_t hlen, gfp_point_t *signature)
{
	gfp_point_t ug, vp, xy;
	bn_t z, invs, u, v, dgst;
	int rlen, shift;

	bn_ba2bn(hash, hlen, dgst);
	rlen = bn_getmsbposn(key->ec.order);
	shift = hlen*8 - rlen;
	if (shift > 0) {
		printf("reduce HASH\n");
		bn_rshift(dgst, shift, dgst);
	}
	bn_invmod(signature->y, key->ec.order, invs);
	bn_mulmod(invs, dgst, key->ec.order, u);
	bn_mulmod(invs, signature->x, key->ec.order, v);
	gf2m_mulmod(&key->ec.g, u, &key->ec, &ug);
	gf2m_mulmod(peer_pub, v, &key->ec, &vp);
	if (gfp_isequal(&ug, &vp))
		gf2m_dblmod(&ug, &key->ec, &xy);
	else
		gf2m_addmod(&ug, &vp, &key->ec, &xy);
	bn_mod(xy.x, key->ec.order, z);
	return !bn_cmp(z, signature->x);
}

