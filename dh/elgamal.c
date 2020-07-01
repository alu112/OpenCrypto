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

#include "elgamal.h"
#include "random.h"
#include "bn.h"

void elg_keygen(elg_prvkey_t *prv)
{
	/* the problem is how to find generator of Zp group */
	/* https://crypto.stackexchange.com/questions/9006/how-to-find-generator-g-in-a-cyclic-group */
	/* http://web.mit.edu/crypto/src/gnupg-1.0.5/cipher/elgamal.c */
}

void elg_encrypt(uint8_t *msg, elg_pubkey_t *pub, uint8_t *ke, uint8_t *cipher)
{
	bn_t key, MSG, KE, km, enc;

	bn_gen_random(MAXBITLEN/2, key);

	bn_hex2bn(msg, MSG);
	bn_expmod(pub->g, key, pub->p, KE);
	bn_expmod(pub->x, key, pub->p, km);
	bn_mulmod(MSG, km, pub->p, enc);
	bn_bn2hex(KE, ke);
	bn_bn2hex(enc, cipher);
}

void elg_decrypt(uint8_t *ke, uint8_t *cipher, elg_prvkey_t *prv, uint8_t *msg)
{
	bn_t KE, MSG, enc, one, pd1, km, invkm;

	bn_hex2bn(ke, KE);
	bn_hex2bn(cipher, enc);
	bn_setone(one);
	bn_sub(prv->p, prv->d, pd1);
	bn_sub(pd1, one, pd1);
	bn_expmod(KE, pd1, prv->p, km);
	bn_eea(prv->p, km, NULL, invkm, NULL);
	bn_mulmod(enc, invkm, prv->p, MSG);
	bn_bn2hex(MSG, msg);
}


