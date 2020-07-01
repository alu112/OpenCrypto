/*
 * https://www.researchgate.net/publication/4107322_Montgomery_modular_multiplication_architecture_for_public_key_cryptosystems
 * 128-bit Montgomery Modular Multiplication Test Vectors 

   li.andrew.mail@gmail.com 
   gavinux@gmail.com

 * r1 is r^(-1)
 * np is n'
 */

#include <stdio.h>
#include "bn.h"

uint8_t n[][64] = {
	"0xeee74404d129949520704c5bf5814703",
	"0xf0fe9f3c608d779379bb3676fdb85071",
	"0xdd54fd6aa41a0dbcb7550b284862b7a5",
	"0x9848765c71a41c12921ca63ca42a203d",
	"0xc71a6ffca861df3a175c6eb226581289"
};

uint8_t np[][64] = {
	"0xa5e0296c5b1d29d6b905ba8ad65d2455",
	"0xcaa42ecf90315ae71b89b6193d868f6f",
	"0x19fac77336272731ae87fe0e59ea7d3",
	"0x77ed2ff5fed15b1c611423518c4488eb",
	"0xe3d08525994d7aa7d1556631cbb4fc47"
};

uint8_t r[] = "0x100000000000000000000000000000000";

uint8_t r1[][64] = {
	"0x9acc3fdac783b519dd82e86481aa4f41",
	"0xbec378d4cd1ac607faef5b46eb7928cd",
	"0x16761e2f9128508ad135cc6b6d6218d",
	"0x4756c6a22f112c1b804bb540fb47b820",
	"0xb12e9e5600d31abbdf15fd645ec00471"
};

uint8_t A[][64] =  {
	"0x223520375bd184b2bac64c9d1a6c55fa",
	"0xadfdb6089758064a69aad900ad18274b",
	"0xc9d5398bf1cec1342f3c7cca33ea04a6",
	"0xc52c1e570e620174fcbb51063ecbfcb1",
	"0xb253687d5f73bacf1fbd542d5d604272"
};

uint8_t B[][64] =  {
	"0xd857ed0720d590d61f05c150e1e40917",
	"0x828994fe60ddcab48671399fd349b0ff",
	"0x2f5bf07df1f473c46318eea49d7f1de3",
	"0x4b1a9caa8e183aabd89e8f3ab7561273",
	"0xaf9764ea40aa14153e8af13177851ab1"
};


uint8_t MonMult[][64] = {
	"0xe3bd635debc8021ea0208d75df078ea6",
	"0xd848da961b4c3092def8bdaca7a73bee",
	"0x7dccdc7deb3d1a1b3afb2b7c0ca5c53a",
	"0x55352eb5475ce94fefcce0a8b687044f",
	"0x8b89addf457e084b752d716c73d29821"
};

extern void bn_mont_mul_2k(bn_t, bn_t, bn_t, bn_t, bn_t);

int main(int argc, char *argv[])
{
	int i, rc;
	bn_t a, b, m, mp, prod, p, P;
	bn_t one, R, Ri;

	rc = 0;
	bn_setone(one);
	for (i=0; i<5; i++) {
		bn_hex2bn(A[i], a);
		bn_hex2bn(B[i], b);
		bn_hex2bn(n[i], m);
		bn_hex2bn(np[i], mp);
		bn_hex2bn(MonMult[i], prod);

//bn_mont_mul_2k(a, b, m, mp, p);
//if (bn_cmp(p, prod)) printf("mont_mul_2k FAILED\n");


		bn_clear(R);
        R[bn_getlen(m)] = 1;
		bn_eea(m, R, mp, Ri, p);
        if (mp[BN_LEN-1] & 1<<31) bn_clear(R);
        bn_sub(R, mp, mp);

		bn_mont_pro(a, b, m, mp, p);
		if (bn_cmp(p, prod)) {
			rc = -1;
			printf("Test %d FAILED\n", i);
		}
		else printf("Test %d PASSED\n", i);

		printf("=========================\n");
		bn_mont_expmod(a, b, m, p);
		bn_print("mont    expmod=0x", p);
		bn_bitwise_expmod(a, b, m, P);
		bn_print("bitwise expmod=0x", P);
		if (bn_cmp(p, P)) {
			rc = -1;
			printf("mont expmod test FAILED\n");
		}
		else printf("mont expmod test PASSED\n");
	}
	printf("-------------------------\n");
	bn_print("xa=0x", a);
	bn_print("xb=0x", b);
	bn_print("xm=0x", m);
	bn_print("mp=0x", mp);
	bn_mulmod(a, b, m, p);
	bn_print("classic mod=0x", p);
	bn_mont_mulmod_with_np(a, b, m, mp, P);
	bn_print("mont  a*b%m=0x", P);
	if (bn_cmp(p, P)) {
		rc = -1;
		printf("mont mulmod test FAILED\n");
	}
	else printf("mont mulmod test PASSED\n");

	printf("=========================\n");
	bn_mont_expmod(a, b, m, p);
	bn_print("mont    expmod=0x", p);
	bn_expmod(a, b, m, P);
	bn_print("classic expmod=0x", P);
	if (bn_cmp(p, P)) {
		rc = -1;
		printf("mont expmod test FAILED\n");
	}
	else printf("mont expmod test PASSED\n");
	return rc;
}

