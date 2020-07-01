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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "bn.h"
#include "ec-gf2m.h"
#include "sha-common.h"

#ifdef EC_TESTVECT
extern bn_t ectest_k;
#else
bn_t ectest_k; /* only allow linking. this prog won't run correctly if EC_TESTVECT not defined */
#endif

int main(int argc, char *argv[])
{
	bool ok;
	int res;
	ec_keyblob_t alice, bob;
	gfp_point_t seca, secb;
	gfp_point_t signature;

	sha_ctx_t sha;
	uint8_t hash[SHA_DIGEST_LENGTH / 8];
#if 0
	uint8_t test[] = "[K-233,SHA-512]";
	uint8_t Msg[] = "72cdef5bdf710978e0aa334b86b8ff4a58630da314eabe98b4d611aab56f55c526983d54d19bbbf9ddba30a84b18aa0bae9f9503e9b222f842f084db83aa39625403213ca321cc0d9c8a136c826e6ea4ec108b913dd0a9ce9d5b8c7e3af53c3876e56a2037ebd6d99f037a097111c837647bedfe4c494e4288ed6427c15969e3";
	uint8_t d[]   = "01df252a11ff97b4421b3a2361db94e908e8243cd50d9179f9e03e331f1";
	uint8_t Qx[]  = "129f011fd5fedf3526f0437ae800a110435db907af60e16912d58523202";
	uint8_t Qy[]  = "08026ed86afa7ec80277f322dfc8cf693089968ed9ceb8c95c930415a23";
	uint8_t k[]   = "04fce14bc83be6f862f06680a32e9a51d1a569fdf1d9b10a89eb9fef4bf";
	uint8_t R[]   = "04d7b8d19dd9cabc3c2245a9d2c8431c3151eeb6f49676a865e78c26c2f";
	uint8_t S[]   = "0373e69da1fe35ce41ff344447fa7ffe6fc71e28dc68244372745739fc2";
	char curve[]  = "sect233k1";
	enum hash_id hash_id = eHASH_SHA512;
#elif 1
	uint8_t test[] = "[K-283,SHA-224]";
	uint8_t Msg[] = "a3ebc17c867cc9c7c28797f6364f6574b80c7ec5b2d8e1542a6f5db8568c15032f92cfbceefa3fe4ee654f690b0455ee5d38dd84bb8665ffc1ff8c849bdbc4aa0ddfdbbca4eb37972fcbcee8cecc1aae21ec736ef61781716b60247b7551ec4e552d0b59a53cec5964c67cf7988787cedf769eabcc9cd5243f58034d96f0e43d";
	uint8_t d[]   = "101c5ed48231a56ca0ea85eb45de0e395e6df2efd4987a226ae36489dd8b2dfbf7c465c";
	uint8_t Qx[]  = "7011260f504d809baefb54af48c890f94fa5984c8bf228baa4b6ea14d46372390d1a8ac";
	uint8_t Qy[]  = "2bbfabb680659aa2611435c4058ed773467a41cdda8250f3490e4f491f1bbae452c5c36";
	uint8_t k[]   = "12a3c7f0b3d64614ff97133873d75c7c1406e316e8cf60d22139dba462055baffe6c8f5";
	uint8_t R[]   = "0a9933496d60716a39e1c3f3bf22a7da546eafebef80dc6f25d0c109ecbc430fdb3e80a";
	uint8_t S[]   = "0be56197a0098b022a7914c10f40207da58403d6c7d04edaf7efc96de740cd71f67e0de";
	char curve[]  = "sect283k1";
	enum hash_id hash_id = eHASH_SHA224;
#else
	uint8_t test[] = "[K-571,SHA-224]";
	uint8_t Msg[] = "964ad0b5acc1c4db6674e86035139f179a9d5ec711b5bae57d2988456bb136d3aade7ac9ef10813e651ae4b9602308b071d75a934a6c012eb90c5eb9b2947b50fc97b1d36c5bf9eb13a7b06c94212c3dcdab402a563262298defff62b836ead1f78f9d20713710fb48115cc5045ba15140fbb4bdf516e4150d830d02cf30963d";
	uint8_t d[]   = "19cf4f4d06825499949f9e0b442586fe1bfe3459813a2b92cd8de0f775a4735e02655702ead8e60824180761808d9e816d60bdb0238e1e8039ca7bb63c92e1cf8433ef447e64ead";
	uint8_t Qx[]  = "07b9cb1728cba80367b62872a986e4fc7f90f269453634d9946f79b1fedf42ca67af93e97ee0601bb3166e85357e8b044e39dcc19e608eaaa8a0066ffc48aa480c0e1e8d5569cbf";
	uint8_t Qy[]  = "580858ab9223c2b2ea58df506d703d64b387a78ef43846894e7a2e47c02252bd2c1e3d21ada7c21d50a08cef0f9a189c4e850c058cc57c37918251b5aaaff2321d7355b6b555644";
	uint8_t k[]   = "0726d5e317f888dddc94c73acb14b320ff509908052868f8c6b14e531ca467c1f7c8287476674efd0d636ca94c24a69d15210bb43a368a11d3453d69ca80430cbfb8b6e45d8f21a";
	uint8_t R[]   = "04ec6205bdd8f7eab414110ed620dd3fbbda4cb3ad9e5559a114ca9344782847621961a3577cbbe43d94eff6ffc8dd7dd09c049239f026a928301ffcddcc910bf196853edc86d31";
	uint8_t S[]   = "16535b1af98a75b9bc0f122ca3ce23a01800fa33b43584a94fd8a8d6f40077eb739f07c9f0e179a157a28023735fc8da2e2ebbee5f7308925900e657fae7c3b321f14fc45346f89";
	char curve[]  = "sect571k1";
	enum hash_id hash_id = eHASH_SHA224;
#endif
	uint8_t msg[1024];
	int mlen;
	gfp_point_t sign;

#ifndef EC_TESTVECT
	printf("This test requires compile as: make clean all CPPFLAGS=\"-DMAXBITLEN=571 -DEC_TESTVECT\"\n");
	return -1;
#endif

	if (MAXBITLEN < 571) {
		printf("compile this test program with: make clean all CPPFLAGS=\"-DMAXBITLEN=571 -DEC_TESTCECT\"\n");
		return -1;
	}
	printf("%s\n", test);
	/* Alice generates a keyblob */
	res = ec_keygen_gf2m(curve, &alice);
	/* Bob   generates a keyblob */
	res |= ec_keygen_gf2m(curve, &bob);
	assert(res > 0);
	bn_print("Alice private key:\nk=", alice.private);
	gfp_print("Alice public  key: ", &alice.public);
	bn_print("Bob   private key:\nk=", bob.private);
	gfp_print("Bob   public  key: ", &bob.public);
	/* Alice calcutes secret and share with Bob */
	ecdh_gf2m(&alice, &bob.public, &seca);
	/* Bob calcutes the shared secret */
	ecdh_gf2m(&bob, &alice.public, &secb);
	gfp_print("alice's secret:", &seca);
	gfp_print("bob's   secret:", &secb);
	if (!gfp_isequal(&seca, &secb))
		printf("Alice's secret != Bob's secret. ECDH Test FAILED\n");
	else
		printf("Alice's secret == Bob's secret. ECDH Test SUCCEED\n");

	mlen = hex2ba(Msg, msg, sizeof(msg));
	printf("msg len = %d\n", mlen);
	bn_hex2bn(d, alice.private);
	bn_hex2bn(Qx, alice.public.x);
	bn_hex2bn(Qy, alice.public.y);
	bn_hex2bn(k, ectest_k);
	bn_hex2bn(R, sign.x);
	bn_hex2bn(S, sign.y);

	memset(hash, 'U', sizeof(hash));
	hash_init(hash_id, &sha);
	sha.update(&sha, msg, mlen);
	sha.final(&sha, hash);
	ecdsa_sign_gf2m(&alice, hash, sha.md_len/8, &signature);
	gfp_print("alice's signature:", &signature);
	if (!bn_cmp(sign.x, signature.x)) printf("sing.x is equal\n");
	else {
		bn_print("x=", sign.x);
		bn_print("X=", signature.x);
	}
	if (!bn_cmp(sign.y, signature.y)) printf("sing.y is equal\n");
	else {
		bn_print("y=", sign.y);
		bn_print("Y=", signature.y);
	}
	if (gfp_isequal(&sign, &signature)) printf("ECDSA sign SUCCEEDED\n");
	else printf("ECDSA sign FAILED\n");
	ok = ecdsa_verify_gf2m(&bob, &alice.public, hash, sha.md_len/8, &signature);
	printf("ECDSA verify: sign.x %s verify.x : verify %s\n", ok ? "==" : "!=", ok ? "SUCCEED" : "FAILED");

	return 0;
}

