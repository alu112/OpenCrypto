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
#include <string.h>
#include "bn.h"
#include "random.h"
#include "primality.h"
#include "rsa.h"

#include <sys/time.h>

#include <time.h>
/*
 * prime generator part of HAC Algorithm 4.86
 * the prime generated from this function is not strong enough,
 * check HAC Algo 4.53 for strong prime
 */
/* this is very slow */
static int get_safe_prime(int kbits, bn_t p)
{
	const int t = 7;

	do {
		get_prime(kbits-1, t, p);
		bn_lshift1(p);
		bn_addx(1, p);
	} while (!is_prime(p, t));
	return 0;
}

/* if e is NULL, then use e, p, q from key */
int rsa_keygen(int keybits, uint8_t *e, rsa_key_t * prv, rsa_key_t * pub)
{
	const int t = 7;
	bn_t px, qx, phi;

	if (keybits > MAXBITLEN) return -1;

	if (e) {
		memset(prv, 0, sizeof(*prv));
		memset(pub, 0, sizeof(*pub));
		if (e == GET_SAFE_PRIME) {
			printf("GET SAFE PRIME\n");
			get_safe_prime(keybits/2, prv->p);
			get_safe_prime(keybits/2, prv->q);
			bn_qw2bn(0x10001, prv->e);
		}
		else {
			printf("GET PRIME\n");
			get_prime(keybits/2, t, prv->p);
			get_prime(keybits/2, t, prv->q);
			printf("GOT PRIME\n");
			bn_hex2bn(e, prv->e);
		}
	}

	//bn_print("rsa_keygen:: p=0x", prv->p);
	//bn_print("rsa_keygen:: q=0x", prv->q);
	//bn_print("e=0x", prv->e);
	bn_mul(prv->p, prv->q, prv->n);
	//bn_print("rsa_keygen:: p*q n=0x", prv->n);

	bn_cpy(prv->p, px); bn_subx(1, px);
	bn_cpy(prv->q, qx); bn_subx(1, qx);
	bn_mul(px, qx,  phi);
	//bn_print("rsa_keygen:: (p-1)*(q-1) phi=0x", phi);

	bn_eea(phi, prv->e, NULL, prv->d, NULL); /* d = inv_e */
	//bn_print("rsa_keygen:: 1/e d=inv_e=0x", prv->d);

	bn_mod(prv->d, px, prv->dp);
	bn_mod(prv->d, qx, prv->dq);
	//bn_print("rsa_keygen:: dp=0x", key->dp);
	//bn_print("rsa_keygen:: dq=0x", key->dq);
	bn_eea(prv->p, prv->q, NULL, prv->invq, NULL);
	//bn_print("rsa_keygen:: 1/q=0x", prv->invq);

	prv->keybits = pub->keybits = keybits;
	bn_cpy(prv->n, pub->n);
	bn_cpy(prv->e, pub->e);

	return 0;
}

/*
 * HAC 14.71 Algorithm Garner’s algorithm for CRT
 * See 14.75 Note (RSA decryption and signature generation)
 * RFC8017 5.2.1
 *
 * BUG:
 *      the out != bitwise_expmod result
 */
void rsa_crt(rsa_key_t *prv, bn_t in, bn_t out)
{
	bn_t h, sp, sq;

	bn_bitwise_expmod(in, prv->dp, prv->p, sp);
	bn_bitwise_expmod(in, prv->dq, prv->q, sq);
	bn_sub(sp, sq, h);
	bn_classic_mulmod(h, prv->invq, prv->p, h);
	bn_mul(prv->q, h, h);
	bn_add(sq, h, out);
}

int rsa_encrypt(rsa_key_t *pub, uint8_t *msg, int bytes, uint8_t *cipher)
{
	bn_t a, c;

	if (bytes*8 > pub->keybits) return -1;
	bn_ba2bn(msg, bytes, a);
	if (bn_cmp(a, pub->n) >= 0) return -2;
	bn_expmod(a, pub->e, pub->n, c);
	bn_bn2ba(c, pub->keybits/8, cipher);
	return 0;
}

int rsa_decrypt(rsa_key_t *prv, uint8_t *cipher, int bytes, uint8_t *msg)
{
	bn_t a, t;

	if (bytes*8 > prv->keybits) return -1;
	bn_ba2bn(cipher, prv->keybits/8, a);
	if (bn_cmp(a, prv->n) >= 0) return -2;
	bn_expmod(a, prv->d, prv->n, t);
	//rsa_crt(prv, a, t);
	bn_bn2ba(t, bytes, msg);
	return 0;
}

int rsa_sign(rsa_key_t *prv, uint8_t *em, int em_bytes, uint8_t *signature)
{
	bn_t a, s;

	if (em_bytes*8 > prv->keybits) return -1;
	bn_ba2bn(em, prv->keybits/8, a);
	if (bn_cmp(a, prv->n) >= 0) return -2;
	bn_expmod(a, prv->d, prv->n, s);
	//rsa_crt(prv, a, s);
	bn_bn2ba(s, prv->keybits/8, signature);
	return 0;
}

int rsa_verify(rsa_key_t *pub, uint8_t *signature, int sign_bytes, uint8_t *em)
{
	bn_t s, sign;

	if (sign_bytes*8 > pub->keybits) return -1;
	bn_ba2bn(signature, pub->keybits/8, sign);
	//bn_mod(a, pub->n, a);
	bn_expmod(sign, pub->e, pub->n, s);
	bn_bn2ba(s, pub->keybits/8, em);
	return 0;
}

