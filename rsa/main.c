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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "random.h"
#include "rsa.h"
#include "rsa-pem.h"

int main(int argc, char *argv[])
{
	uint8_t msg[] = {"Hello World From My Crypto Toy!\n"};
	uint8_t dec[MAXBITLEN/8];
	uint8_t cipher[2*MAXBITLEN/8 + 3]; /* 3 for 0x and '\0' */
	uint8_t hash0[sizeof(cipher)], hash1[sizeof(cipher)];
	uint8_t sign[sizeof(cipher)];
	int rc;
	rsa_key_t pub, prv;

	if (argc != 5) {
		printf("Usage:\n");
		printf("    %s openssl_pub.pem openssl_prv.pem reproduced_pub.pem reproduced_prv.pem\n", argv[0]);
		printf("command to create PEM files:\n");
		printf("    openssl genrsa -out prv.pem\n");
		printf("    openssl rsa -in prv.pem -pubout > pub.pem\n\n");
		exit(-1);
	}

	memset(&prv, 0, sizeof(prv));
	memset(&pub, 0, sizeof(pub));

	if (rsa_pem2pubkey(argv[1], &pub))
		printf("rsa_pem2pubkey() failed\n");
	if (rsa_pubkey2pem(&pub, argv[3]))
		printf("rsa_pubkey2pem() failed\n");
	if (rsa_pem2prvkey(argv[2], &prv))
		printf("rsa_pem2prvkey() failed\n");
	if (rsa_prvkey2pem(&prv, argv[4]))
		printf("rsa_prvkey2pem() failed\n");
	uint8_t e[] = {"0x10001"}; rc = rsa_keygen(2048,    e, &prv, &pub); /* generate my own keys, any prime */
	//rc = rsa_keygen(2048, USE_PQE_IN_PRV, &prv, &pub); /* use p,q,e from PEM file: very fast */
	//rc = rsa_keygen(2048, GET_SAFE_PRIME, &prv, &pub); /* generate my own keys, saf_prime: very slow */
	if (rc) printf("rsa_keygen failed\n");

	rc = rsa_encrypt(&pub, msg, sizeof(msg), cipher);
	if (rc) printf("rsa_encrypt failed: %d\n", rc);
	//printf("cipher=%s\n", cipher);

	rc = rsa_decrypt(&prv, cipher, sizeof(msg), dec);
	if (rc) printf("rsa_decrypt failed: %d\n", rc);
	printf("msg=%s\n", dec);

	//bn_t   hash;
	//bn_gen_random(bn_getmsbposn(prv.n) - 1, hash);
	//bn_bn2ba(hash, prv.keybits/8, hash0);
	memset(hash0, 0, sizeof(hash0));
	get_random(bn_getmsbposn(prv.n)-1, hash0);

	rc = rsa_sign(&prv, hash0, prv.keybits/8, sign);
	if (rc) printf("rsa sign failed %d\n", rc);
	rc = rsa_verify(&pub, sign, pub.keybits/8, hash1);
	if (rc) printf("signature verify failed in calculate HASH: %d\n", rc);
	else {
		rc = memcmp(hash0, hash1, pub.keybits/8);
		if (rc) {
			int i;
			for (i=0; i<pub.keybits/8; i++) printf("%02x", hash0[i]); printf("\n");
			for (i=0; i<pub.keybits/8; i++) printf("%02x", hash1[i]); printf("\n");
		}
		printf("signature verify %s\n", rc ? "FAILED" : "SUCCEEDED");
	}

	return rc;
}

