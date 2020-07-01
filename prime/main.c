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

#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include "bn.h"
#include "primality.h"
#include "random.h"

int main(void)
{
	uint8_t prime_yes[] = {"b9746a51b84217152fd9e8a67970b613cabd88d425070571"};
	uint8_t prime_no[]  = {"b9746a51b84217152fd9e8a67970b613cabd88d425070511"};

	uint8_t primes[][256+8] = {
		{"0x9b93aa2dd1a167c5859bc62d5df9e9a2c99aa50dd6d9d192989ec2961acc2cd62c76cb34ebf98792b7d6f030fb4dad0f8ef4b4e35e89af9156dc51d77c5da278bb6c7e2352c98f5416dbd377439f4fbcd3b7d00e321d67a316d064b83cbcc210b6c568fb80610ccdad1fbb64a2863b979edb64b2ce00c5ff14f97356211c1ce7"},
		{"0x9e292ae56ed7c751f6a392a84ea8ced22592230e3b490673226a99a5ea1a1a6a157d539c6abaf51541a056ffd2eefc0fc710ee892da3caa6c83abb186508bb6750dc423511ed8a0883bdbf8d54ea2cc386df82ed50e887644cb7869151400063943216ea79aca8138779520028011ebdb6443fd06d9118624ff99c261e533c17"},
		{"0x0efd19f2e8e87c453b59401661bb58f97b1ea71949ea3ae7b31359bfc34e7739c6776eedea9771ce830d8185e20d"},
		{"0x047a095d446066c0b87c0275f2d2cab77570e1eb88cd4564f5d954859544e70927423c0f7c640cf2cbfa05bbdd0d"},
		{"0x0a82ad1ecb13aacc42c1cbadab959b9a1e7a3d0918f161a28dc9b2471ec06f4891db344c75ee700103b5a1a2f3d1"},
		{"0x20c0b99c474406d68b8eb20b10ed3271374fd135e45a84cba9b48c875c658962bf77e4212913e13c4f8a303347ef"},
		{"0x0e0d00c96e00ccf3e3be34cd630be9d6021c863846f5d07d2c71a69e3c84dbd8d7282d08e8a7d968050cc94e7bd9"},
		{"0x0d2b056abc94061a4dc14df365003e29291a5dbc939084e4646930592bde910ed5e8a777e855291866c0ec9f06fb"},
		{"0x05ff23a9608f41eee7c33f36349a995b653ffa1a65ebba86506ff17b26fa84d124dc7901025d7fb553551b07dec7"},
		{"0x047024e9ce77cd142ca88c8b7dd4697ec6fe502f8aac8d7e6f730b6a425c73b7279b953afb8799604c0c9a6e55bd"},
		{"0x0f70a1f5fee022508a98396bd5df4710666d054a2ae914f862724527f4493560cc2a54b465de06fab4cac865c7af"},
		{"0x06a240c418491a3f4782922cb2fef8b75a70a6514cb5ffec4e75a76762d3e0f657debbc91822a4c1e1e1e64e8015"},
	};

	int i, k = 7;
	bn_t p;
	for (i=0; i<1000; i++) {
		bn_gen_random(BN_LEN, p);
		if (is_prime(p, k)) printf("v");
		else printf(".");
		fflush(stdout);
	}
	for (i=0; i<1000; i++) {
		get_prime(BN_LEN*32/2, k, p);
	}
	for (i=0; i<ARRAY_SIZE(primes); i++) {
		bn_hex2bn(primes[i], p);
		printf("%s\n", is_prime(p, k) ? "yes" : "no");
	}

	bn_qw2bn(7, p);
	printf("%s\n", is_prime(p, k) ? "yes" : "no");

	bn_hex2bn(prime_yes, p);
	printf("%s\n", is_prime(p, k) ? "yes" : "no");

	bn_hex2bn(prime_no, p);
	printf("%s\n", is_prime(p, k) ? "yes" : "no");


	return 0;
}

