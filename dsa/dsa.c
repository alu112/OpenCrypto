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
#include <stdbool.h>
#include "dsa.h"
#include "bn.h"
#include "random.h"
#include "primality.h"
#include "sha1.h"

extern int get_dsa_param(uint32_t keylen, dsa_param_t *dsa);

#ifdef DSA_TESTVECT
bn_t test_d;
bn_t test_k;
#endif
/*
 * a^k mod p = 1
 * order = k;
 */
static void ord(bn_t p, bn_t k, bn_t a)
{
	bn_t alpha, one;
	bn_setone(alpha);
	bn_setone(one);
	do{
		bn_add(alpha, one, alpha);
		bn_expmod(alpha, k, p, a);
	}
	while(bn_isone(a));
	bn_cpy(alpha, a);
}

static void gen_prime(int plen, int qlen, bn_t pout, bn_t qout)
{
	int i;
	bool fin = false;
	bn_t p, q, q2, two, one, rem, pm1;
	bn_clear(p);
	bn_clear(q);
	bn_setone(one);
	bn_setone(two);
	bn_add(two, one, two);
	printf("qlen: %d", qlen);
	while(1){
		do{
			bn_gen_random(qlen-1, q);
		}while(!is_prime(q, 3));
		printf("\nfound q prime ");
		bn_print("q = ", q);
		bn_mul(q, two, q2);
		for( i = 1; i < 4096; i ++){
			bn_gen_random(plen-1, p);
			if(bn_isodd(p)){
				bn_sub(p, one, pm1);
				bn_mod(pm1, q, rem);
			}
			else continue;
			if(is_prime(p, 3) && bn_iszero(rem)){
				bn_cpy(p, pout);
				bn_cpy(q, qout);
				fin = true;
				printf("inside");
				break;
			}
		}
		if(fin) break;
	}
	printf("prime found");
}

void dsa_keygen(uint32_t keylen, dsa_key_t *key)
{
	int len, qlen, rc;
	bn_t p, rem, res;
	dsa_param_t *params;

	params = &key->dsa;
	switch (keylen) {
		case 1024: qlen = 160; break;
		case 2048: qlen = 224; break;
		case 3072: qlen = 256; break;
	}
	/* get dsa parameters */
	rc = get_dsa_param(keylen, &key->dsa);
	if (rc) {
		gen_prime(keylen, qlen, params->p, params->q);
		bn_cpy(params->p, p);
		bn_subx(1, p);
		bn_div(p, params->q, res, rem);
		ord(params->p, params->q, params->g);
		len = bn_getmsbposn(params->q);
	}
	/* generate private key */
	do {
		bn_gen_random(len, key->prv);
	} while (bn_cmp(params->q, key->prv) > 0);
#ifdef DSA_TESTVECT
	printf("copy test private key\n");
	bn_cpy(test_d, key->prv);
#endif
	/* generate public key */
	bn_expmod(params->g, key->prv, params->p, key->pub);
}

void dsa_sign(dsa_key_t *key, uint8_t *hash, uint32_t hlen, dsa_sig_t *sign)
{
	int len, shift;
	bn_t dr, hdr, invk, dgst, k;
	dsa_param_t *params;

	params = &key->dsa;
	do {
		bn_gen_random(params->keylen/2, k);
	} while(bn_cmp(params->g, k));
#ifdef DSA_TESTVECT
	printf("copy test k\n");
	bn_cpy(test_k, k);
#endif
	bn_expmod(params->g, k, params->p, sign->r);
	bn_mod(sign->r, params->q, sign->r);
	bn_ba2bn(hash, hlen, dgst);
	len = bn_getmsbposn(params->q);
	shift = hlen*8-len;
	if(len < hlen*8){
		bn_rshift(dgst, shift, dgst);
	}

	bn_mulmod(key->prv, sign->r, params->q, dr);
	bn_addmod(dgst, dr, params->q, hdr);
	bn_invmod(k, params->q, invk);
	bn_mulmod(invk, hdr, params->q, sign->sig);
}

bool dsa_verify (dsa_key_t *key, uint8_t * hash, uint32_t hlen, dsa_sig_t *sign)
{
	int len, shift;
	bn_t u1, u2, v, vaux1, vaux2, vp, invs, dgst;
	dsa_param_t *params;

	params = &key->dsa;
	bn_invmod(sign->sig, params->q, invs);

	bn_ba2bn(hash, hlen, dgst);
	len = bn_getmsbposn(params->q);
	shift = hlen*8-len;
	if(shift > 0){
		bn_rshift(dgst, shift, dgst);
	}
	/* compute v */
	bn_mulmod(invs, dgst, params->q, u1);
	bn_mulmod(invs, sign->r, params->q, u2);
	bn_expmod(params->g, u1, params->p, vaux1);
	bn_expmod(key->pub, u2, params->p, vaux2);
	bn_mulmod(vaux1, vaux2, params->p, v);
	bn_mod(v, params->q, v);

	/* compare r mod q to v */
	bn_mod(sign->r, params->q, vp);
	return !bn_cmp(v, vp);
}

