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

int mulmod_benchmark(void)
{
	int i;
	struct timeval tv0, tv1;
	uint64_t diff;
	bn_t a, b, n, y0, y1;
	uint8_t nt[] = "bad47a84c1782e4dbdd913f2a261fc8b65838412c6e45a2068ed6d7f16e9cdf4462b39119563cafb74b9cbf25cfd544bdae23bff0ebe7f6441042b7e109b9a8afaa056821ef8efaab219d21d6763484785622d918d395a2a31f2ece8385a8131e5ff143314a82e21afd713bae817cc0ee3514d4839007ccb55d68409c97a18ab62fa6f9f89b3f94a2777c47d6136775a56a9a0127f682470bef831fbec4bcd7b5095a7823fd70745d37d1bf72b63c4b1b4a3d0581e74bf9ade93cc46148617553931a79d92e9e488ef47223ee6f6c061884b13c9065b591139de13c1ea2927491ed00fb793cd68f463f5f64baa53916b46c818ab99706557a1c2d50d232577d1";
	uint8_t at[] = "e7c9e4b3efd7ac9e83be08328105356dfeefe222f26c95378effd2150fadf7ba23f5b4705d82e4f1bc45057067c7def73e2100f756ee6d547965fa4f24b85d68867f03d7c886d1dbcca4c589745701b362a1f1417f471d8475b6b7a16a4c48ef1f556edc3f0ff6ba13d365d6e82751f207d91101c8eea1013ccdd9e1de4c387f";
	uint8_t bt[] = "ce58602e051f0f4f47c4ec57f682e5737fc482a8a1ffac9043bba4fba3387d7dd2154507af1e28bd81b61fcdfe35f9734e0d9b53682ec785f1f6e6224f63d10bf78484b83a4254f333d0fb3f3e9e1834bede52e3078ac279a862fb90af266d7591c81f20b718d07d51bfc221b66a25403b4ac1a68d673fdd959b01ecf3d0a7af";

	bn_hex2bn(bt, b);
	bn_hex2bn(at, a);
	bn_hex2bn(nt, n);

	/* bitwise_mulmod is the most reliable algo */
	gettimeofday(&tv0, NULL);
	for (i=0; i<10; i++) {
		bn_classic_mulmod(a, b, n, y0);
	}
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("classic_mulmod time=%ld us\n", diff);

	bn_mont_pro = bn_mont_pro_1;
	gettimeofday(&tv0, NULL);
	for (i=0; i<10; i++) {
		bn_mont_mulmod(a, b, n, y1);
	}
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("mont_mulmod1 time=%ld us\n", diff);
	if (bn_cmp(y1, y0)) printf("classic_mulmod != mont_mulmod1\n");

	bn_mont_pro = bn_mont_pro_2;
	gettimeofday(&tv0, NULL);
	for (i=0; i<10; i++) {
		bn_mont_mulmod(a, b, n, y1);
	}
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("mont_mulmod2 time=%ld us\n", diff);
	if (bn_cmp(y1, y0)) printf("classic_mulmod != mont_mulmod2\n");

	bn_mont_pro = bn_mont_pro_3;
	gettimeofday(&tv0, NULL);
	for (i=0; i<10; i++) {
		bn_mont_mulmod(a, b, n, y1);
	}
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("mont_mulmod3 time=%ld us\n", diff);
	if (bn_cmp(y1, y0)) printf("classic_mulmod != mont_mulmod3\n");
}

int expmod_benchmark(void)
{
        int i;
	struct timeval tv0, tv1;
	uint64_t diff;
        bn_t a, b, n, y0, y1, y2;

	uint8_t nt[] = "bad47a84c1782e4dbdd913f2a261fc8b65838412c6e45a2068ed6d7f16e9cdf4462b39119563cafb74b9cbf25cfd544bdae23bff0ebe7f6441042b7e109b9a8afaa056821ef8efaab219d21d6763484785622d918d395a2a31f2ece8385a8131e5ff143314a82e21afd713bae817cc0ee3514d4839007ccb55d68409c97a18ab62fa6f9f89b3f94a2777c47d6136775a56a9a0127f682470bef831fbec4bcd7b5095a7823fd70745d37d1bf72b63c4b1b4a3d0581e74bf9ade93cc46148617553931a79d92e9e488ef47223ee6f6c061884b13c9065b591139de13c1ea2927491ed00fb793cd68f463f5f64baa53916b46c818ab99706557a1c2d50d232577d1";
	uint8_t at[] = "e7c9e4b3efd7ac9e83be08328105356dfeefe222f26c95378effd2150fadf7ba23f5b4705d82e4f1bc45057067c7def73e2100f756ee6d547965fa4f24b85d68867f03d7c886d1dbcca4c589745701b362a1f1417f471d8475b6b7a16a4c48ef1f556edc3f0ff6ba13d365d6e82751f207d91101c8eea1013ccdd9e1de4c387f";
	uint8_t bt[] = "ce58602e051f0f4f47c4ec57f682e5737fc482a8a1ffac9043bba4fba3387d7dd2154507af1e28bd81b61fcdfe35f9734e0d9b53682ec785f1f6e6224f63d10bf78484b83a4254f333d0fb3f3e9e1834bede52e3078ac279a862fb90af266d7591c81f20b718d07d51bfc221b66a25403b4ac1a68d673fdd959b01ecf3d0a7af";

	bn_hex2bn(bt, b);
	bn_hex2bn(at, a);
	bn_hex2bn(nt, n);

        /* bitwise_mulmod is the most reliable algo */
        gettimeofday(&tv0, NULL);
        for (i=0; i<10; i++) {
                bn_bitwise_expmod(a, b, n, y0);
        }
        gettimeofday(&tv1, NULL);
        diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
        diff = diff + tv1.tv_usec - tv0.tv_usec;
        printf("bitwise_expmod time=%ld us\n", diff);

        gettimeofday(&tv0, NULL);
        for (i=0; i<10; i++) {
                bn_kary_expmod(a, b, n, y1);
        }
        gettimeofday(&tv1, NULL);
        diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
        diff = diff + tv1.tv_usec - tv0.tv_usec;
        printf("kary_expmod time=%ld us\n", diff);
        if (bn_cmp(y1, y0)) printf("bitwise_expmod != kary_expmod\n");

        gettimeofday(&tv0, NULL);
        for (i=0; i<10; i++) {
                bn_mont_expmod(a, b, n, y2);
        }
        gettimeofday(&tv1, NULL);
        diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
        diff = diff + tv1.tv_usec - tv0.tv_usec;
        printf("mont_expmod time=%ld us\n", diff);
        if (bn_cmp(y2, y0)) printf("bitwise_expmod != mont_expmod\n");
}

int main(void)
{
	struct timeval tv0, tv1;
	uint64_t diff;
	bn_t a, b, r, q, n, num, x, y;

	bn_qw2bn(72639, a);
	bn_qw2bn(1, x);
	bn_qw2bn(7118368, b);
	bn_mont_redc(a, x, b, r);

	bn_qw2bn(693, x);
	bn_qw2bn(609, y);
	gettimeofday(&tv0, NULL);
	for (int i=0; i<1000; i++)
		bn_eea(x, y, a, b, r);
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("time=%ld us\n", diff);
	bn_print("a=", a);
	bn_print("b=", b);
	bn_print("r=", r);
	printf("-----------------------------\n");
	bn_qw2bn(693, x);
	bn_qw2bn(609, y);
	gettimeofday(&tv0, NULL);
	for (int i=0; i<1000; i++)
		bn_bin_extended_gcd(x, y, a, b, r);
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("time=%ld us\n", diff);
	bn_print("a=", a);
	bn_print("b=", b);
	bn_print("r=", r);
	printf("-----------------------------\n");

	bn_hex2bn("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", x);
	bn_sqr(x, y);
	bn_print(" x=0x", x);
	bn_print("xx=0x", y);

	mulmod_benchmark();
	expmod_benchmark();

	bn_hex2bn("0xb9746a51b8421715264564545235fd9e8a67970b613dbfad2a6cabd88d425070", b);
	bn_hex2bn("0x814351dbcfba989018042039482042834798327498ddeadb", a);
	//bn_hex2bn(  "0xffffffffffffffffffffffffffffffffffffffffffffffff", a);
	bn_hex2bn("0x81111768646523abcdefeee45cdeafb678", n);

	gettimeofday(&tv0, NULL);
	for (int i=0; i<1000; i++)
		bn_bin_gcd(a, b, q);
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("time=%ld us\n", diff);
	bn_print("gcd=", q);

	bn_print("b=", b);
	bn_print("a=", a);
	gettimeofday(&tv0, NULL);
	//for (int i=0; i<1000000; i++)
	bn_div(b, a, q, r);
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("time=%ld us\n", diff);
	bn_print("b/a=", q);
	bn_print("b%a=", r);

	gettimeofday(&tv0, NULL);
	//for (int i=0; i<1000000; i++)
	bn_div(b, a, q, r);
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("time=%ld us\n", diff);
	bn_print("b/a=", q);
	bn_print("b%a=", r);
	return 0;
	bn_qw2bn(1, a);
	bn_qw2bn(0x10001, b);
	bn_mul(a, b, r);
	bn_print("r=0x",r);
	bn_mul(b, a, r);
	bn_print("r=0x",r);

	/* GF(p) */
	bn_hex2bn("0x814351dbcfba989018042039482042834798327498ddeadb", a);
	bn_hex2bn("0xb9746a51b8421715264564545235fd9e8a67970b613dbfad2a6cabd88d425070571", b);
	bn_hex2bn("0x81111768646523abcdefeee45cdeafb678", n);
	bn_print("a=", a);
	bn_print("b=", b);
	bn_mul(a, b, n);
	bn_print("a*b=", n);
	bn_div(b, a, q, r);
	bn_print("b/a=", q);
	bn_print("b%a=", r);

	printf("========bn_expmod==========\n");
	gettimeofday(&tv0, NULL);
	bn_expmod(a, b, n, y);
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("time=%ld us\n", diff);
	bn_print("n=", n);
	bn_print("a^b%n=", y);
	printf("\n");
	gettimeofday(&tv0, NULL);
	bn_expmod(a, b, n, y);
	gettimeofday(&tv1, NULL);
	diff = (tv1.tv_sec - tv0.tv_sec) * 1000000UL;
	diff = diff + tv1.tv_usec - tv0.tv_usec;
	printf("time=%ld us\n", diff);
	bn_print("a^b%n=", y);

	/* GF(2^m) */
	bn_hex2bn("0xab0q9840809459435fecdef8", a);
	bn_hex2bn("0x1239898bbcdfe38", b);
	bn_mul_gf2m(a, b, x);
	bn_print("0x", x);
	bn_hex2bn("3", num);
	bn_add_gf2m(x, num, x);
	bn_print("x=0x", x);
	bn_print("b=0x", b);
	bn_invmod_gf2m(x, b, a);
	bn_print("inv=0x", a);

	bn_qw2bn(0x53, a);
	bn_qw2bn(0xca, b);
	bn_qw2bn(0x11b, n);
	bn_mulmod_gf2m(a, b, n, x);
	bn_print("a=", a); bn_print("b=", b); bn_print("n=", n);
	bn_print("a*b=", x);
	bn_hex2bn("0x20000000000000000000000000000000000000004000000000000000001", n);
	bn_hex2bn("0x1812e1c97127e9a037581fdb6ad1178330557463c38e4b00197abf9833f", a);
	bn_hex2bn("0x17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126", a);
	bn_hex2bn("0x184abdf8a3fe51502bbfb95a4fa4248623b7f300f789e980da22227eea3", a);
	bn_print("  n=", n);
	bn_print("  a=", a);
	bn_invmod_gf2m(a, n, b);
	bn_print("1/a=", b);
	bn_mulmod_gf2m(a, b, n, x);
	bn_print("a* 1/a=", x);
	printf("--------------\n");
	bn_print("  n=", n);
	bn_print("  a=", a);
	bn_invmod_gf2m(a, n, b);
	bn_print("1/a=", b);
	bn_mulmod_gf2m(a, b, n, x);
	bn_print("a* 1/a=", x);
	printf("--------------\n");

	bn_hex2bn("0x10000e2", a);
	bn_hex2bn("0x2000009", n);
	bn_print("  n=", n);
	bn_print("  a=", a);
	bn_invmod_gf2m(a, n, b);
	bn_print("1/a=", b);
	bn_mulmod_gf2m(a, b, n, x);
	bn_print("a* 1/a=", x);

	return 0;
}

