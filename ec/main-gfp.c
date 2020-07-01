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
#include <string.h>
#include "ec-gfp.h"
#include "ec-pem.h"
#include "sha-common.h"

#ifdef EC_TESTVECT
extern bn_t ectest_k;
#else
bn_t ectest_k; /* only allow linking. this prog won't run correctly if EC_TESTVECT not defined */
#endif

int main(int argc, char *argv[])
{
	int res = 0;
	bool ok = 1;
	ec_keyblob_t alice, bob;
	gfp_point_t seca, secb;
	gfp_point_t signature;
	uint8_t hash[SHA_DIGEST_LENGTH / 8];

	if (argc != 5 && argc != 1) {
		printf("Usage:\n");
		printf("    %s openssl_pub.pem openssl_prv.pem reproduced_pub.pem reproduced_prv.pem\n", argv[0]);
		printf("command to create Elliptic Curve PEM files:\n");
		printf("    openssl ecparam -name prime256v1 -genkey -out prime256v1prv.pem\n");
		printf("    openssl ec -in prime256v1prv.pem -pubout -out prime256v1pub.pem\n\n");
		exit(-1);
	}

	if (argc == 5) {
		ec_keyblob_t ec;
		memset(&ec, 0, sizeof(ec));

		ec_pem2pubkey(argv[1], &ec);
		ec_pubkey2pem(&ec, argv[3]);

		ec_pem2prvkey(argv[2], &ec);
		ec_prvkey2pem(&ec, argv[4]);


		/* Alice generates a keyblob */
		res |= ec_keygen_gfp("prime256v1", &alice);
		/* Bob   generates a keyblob */
		res |= ec_keygen_gfp("prime256v1", &bob);
		assert(res > 0);
		/* Alice calcutes secret and share with Bob */
		ecdh_gfp(&alice, &bob.public, &seca);
		/* Bob calcutes the shared secret */
		ecdh_gfp(&bob, &alice.public, &secb);
		gfp_print("alice's secret:", &seca);
		gfp_print("bob's   secret:", &secb);
		if (!gfp_isequal(&seca, &secb))
			printf("Alice's secret != Bob's secret. ECDH Test FAILED\n");
		else
			printf("Alice's secret == Bob's secret. ECDH Test SUCCEED\n");

		get_random(SHA1_DIGEST_LENGTH/8, hash);

		ecdsa_sign_gfp(&alice, hash, SHA1_DIGEST_LENGTH/8, &signature);
		gfp_print("alice's signature:", &signature);
		ok = ecdsa_verify_gfp(&bob, &alice.public, hash, SHA1_DIGEST_LENGTH/8, &signature);
		printf("ecdsa verify: sign.x %s verify.x : verify %s\n", ok ? "==" : "<>", ok ? "ECDSA SUCCEED" : "ECDSA FAILED");
		if (!ok) return -1;
	}
	if (!ok) return -1;

#ifdef EC_TESTVECT
	printf("\nRFC4754 Test Case\n");
	if (MAXBITLEN < 256) {
		printf("You have to use this command to compile test code:\n");
		printf("    make clean all CPPFLAGS=\"-DMAXBITLEN=256 -DEC_TESTVECT\"\n");
	}
	res |= ec_keygen_gfp("prime256v1", &alice);
	res |= ec_keygen_gfp("prime256v1", &bob);
	/* RFC4754 test vector for prime256v1 section 8.1 */
	bn_hex2bn("0xDC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F", alice.private);
	/* calculate pub key from RFC4754 test vector */
	gfp_mulmod(&alice.ec.g, alice.private, &alice.ec, &alice.public);
	bn_t gwx, gwy;
	bn_hex2bn("0x2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970", gwx);
	bn_hex2bn("0x6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D", gwy);
	assert(!bn_cmp(gwx, alice.public.x));
	assert(!bn_cmp(gwy, alice.public.y));
	/* hash of "abc" from RFC4754 */
	int hlen = hex2ba("0xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", hash, sizeof(hash));
	printf("hash length=%d\n", hlen);
	bn_hex2bn("0x9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE", ectest_k);

	ecdsa_sign_gfp(&alice, hash, hlen, &signature);
	gfp_print("signature:", &signature);
	bn_t r, s;
	bn_hex2bn("0xCB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C", r);
	bn_hex2bn("0x86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315", s);
	bn_print("R=", r);
	bn_print("S=", s);
	assert(!bn_cmp(r, signature.x));
	assert(!bn_cmp(s, signature.y));

	gfp_point_t verify;
	bn_hex2bn("0xCB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C", verify.x);
	bn_hex2bn("0x86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315", verify.y);
	ok = ecdsa_verify_gfp(&bob, &alice.public, hash, hlen, &verify);
	printf("ecdsa verify: %s\n", ok ? "SUCCEED" : "FAILED");
	if (!ok) return -2;
	bn_hex2bn("0x2B57C0235FB7489768D058FF4911C20FDBE71E3699D91339AFBB903EE17255DC", verify.y);
	ok = ecdsa_verify_gfp(&bob, &alice.public, hash, hlen, &verify);
	printf("ecdsa verify: %s\n", ok ? "SUCCEED, It should FAIL!!!" : "FAILED, It should FAIL!!!");

	if (ok) return -2;
#endif


#ifdef EC_TESTVECT
#if 0
	uint8_t test[] = "[P-256]";
	uint8_t Msg[] = "5ff1fa17c2a67ce599a34688f6fb2d4a8af17532d15fa1868a598a8e6a0daf9b11edcc483d11ae003ed645c0aaccfb1e51cf448b737376d531a6dcf0429005f5e7be626b218011c6218ff32d00f30480b024ec9a3370d1d30a9c70c9f1ce6c61c9abe508d6bc4d3f2a167756613af1778f3a94e7771d5989fe856fa4df8f8ae5";
	uint8_t d[]   = "002a10b1b5b9fa0b78d38ed29cd9cec18520e0fe93023e3550bb7163ab4905c6";
	uint8_t Qx[]  = "e9cd2e8f15bd90cb0707e05ed3b601aace7ef57142a64661ea1dd7199ebba9ac";
	uint8_t Qy[]  = "c96b0115bed1c134b68f89584b040a194bfad94a404fdb37adad107d5a0b4c5e";
	uint8_t k[]   = "00c2815763d7fcb2480b39d154abc03f616f0404e11272d624e825432687092a";
	uint8_t R[]   = "15bf46937c7a1e2fa7adc65c89fe03ae602dd7dfa6722cdafa92d624b32b156e";
	uint8_t S[]   = "59c591792ee94f0b202e7a590e70d01dd8a9774884e2b5ba9945437cfed01686";
	char curve[]  = "prime256v1";
	enum hash_id hash_id = eHASH_SHA1;

#elif 1
	uint8_t test[] = "[P-256,SHA-384]";
	uint8_t Msg[] = "e0b8596b375f3306bbc6e77a0b42f7469d7e83635990e74aa6d713594a3a24498feff5006790742d9c2e9b47d714bee932435db747c6e733e3d8de41f2f91311f2e9fd8e025651631ffd84f66732d3473fbd1627e63dc7194048ebec93c95c159b5039ab5e79e42c80b484a943f125de3da1e04e5bf9c16671ad55a1117d3306";
	uint8_t d[]   = "b6faf2c8922235c589c27368a3b3e6e2f42eb6073bf9507f19eed0746c79dced";
	uint8_t Qx[]  = "e0e7b99bc62d8dd67883e39ed9fa0657789c5ff556cc1fd8dd1e2a55e9e3f243";
	uint8_t Qy[]  = "63fbfd0232b95578075c903a4dbf85ad58f8350516e1ec89b0ee1f5e1362da69";
	uint8_t k[]   = "9980b9cdfcef3ab8e219b9827ed6afdd4dbf20bd927e9cd01f15762703487007";
	uint8_t R[]   = "f5087878e212b703578f5c66f434883f3ef414dc23e2e8d8ab6a8d159ed5ad83";
	uint8_t S[]   = "306b4c6c20213707982dffbb30fba99b96e792163dd59dbe606e734328dd7c8a";
	char curve[]  = "prime256v1";
	enum hash_id hash_id = eHASH_SHA384;
#else
	uint8_t test[] = "[P-521,SHA-224]";
	uint8_t Msg[] = "58ec2b2ceb80207ff51b17688bd5850f9388ce0b4a4f7316f5af6f52cfc4dde4192b6dbd97b56f93d1e4073517ac6c6140429b5484e266d07127e28b8e613ddf65888cbd5242b2f0eee4d5754eb11f25dfa5c3f87c790de371856c882731a157083a00d8eae29a57884dbbfcd98922c12cf5d73066daabe3bf3f42cfbdb9d853";
	uint8_t d[]   = "1d7bb864c5b5ecae019296cf9b5c63a166f5f1113942819b1933d889a96d12245777a99428f93de4fc9a18d709bf91889d7f8dddd522b4c364aeae13c983e9fae46";
	uint8_t Qx[]  = "1a7596d38aac7868327ddc1ef5e8178cf052b7ebc512828e8a45955d85bef49494d15278198bbcc5454358c12a2af9a3874e7002e1a2f02fcb36ff3e3b4bc0c69e7";
	uint8_t Qy[]  = "184902e515982bb225b8c84f245e61b327c08e94d41c07d0b4101a963e02fe52f6a9f33e8b1de2394e0cb74c40790b4e489b5500e6804cabed0fe8c192443d4027b";
	uint8_t k[]   = "141f679033b27ec29219afd8aa123d5e535c227badbe2c86ff6eafa5116e9778000f538579a80ca4739b1675b8ff8b6245347852aa524fe9aad781f9b672e0bb3ff";
	uint8_t R[]   = "06b973a638bde22d8c1c0d804d94e40538526093705f92c0c4dac2c72e7db013a9c89ffc5b12a396886305ddf0cbaa7f10cdd4cd8866334c8abfc800e5cca365391";
	uint8_t S[]   = "0b0a01eca07a3964dd27d9ba6f3750615ea36434979dc73e153cd8ed1dbcde2885ead5757ebcabba117a64fcff9b5085d848f107f0c9ecc83dfa2fa09ada3503028";
	char curve[]  = "secp521r1";
	enum hash_id hash_id = eHASH_SHA224;
#endif
	uint8_t msg[1024];
	int mlen;
	sha_ctx_t sha;
	gfp_point_t sign;

	if (MAXBITLEN < 571) {
		printf("You have to use this command to compile test code:\n");
		printf("    make clean all CPPFLAGS=\"-DMAXBITLEN=571 -DEC_TESTVECT\"\n");
		return -1;
	}

	printf("%s\n", test);
	ec_keygen_gfp(curve, &alice);
	ec_keygen_gfp(curve, &bob);

	mlen = hex2ba(Msg, msg, sizeof(msg));
	printf("msg len = %d\n", mlen);
	bn_hex2bn(d, alice.private);
	bn_hex2bn(Qx, alice.public.x);
	bn_hex2bn(Qy, alice.public.y);
	bn_hex2bn(k, ectest_k);
	bn_hex2bn(R, sign.x);
	bn_hex2bn(S, sign.y);

	hash_init(hash_id, &sha);
	sha.update(&sha, msg, mlen);
	sha.final(&sha, hash);

	ecdsa_sign_gfp(&alice, hash, sha.md_len/8, &signature);
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
	ok = ecdsa_verify_gfp(&bob, &alice.public, hash, sha.md_len/8, &signature);
	printf("ECDSA verify: sign.x %s verify.x : verify %s\n", ok ? "==" : "!=", ok ? "SUCCEED" : "FAILED");

	if (!ok) return -3;
#endif

	return 0;
}

