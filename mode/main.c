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
#include <string.h>
#include "des.h"
#include "aes.h"
#include "paddings.h"
#include "cipher-mode.h"

static void printbuf(uint8_t *buf, int nr)
{
	int i, j;
	for (i=0; i<nr/16; i++) {
		for (j=0; j<16; j++)
			printf("%02x ", buf[i*16+j]);
		printf("\n");
	}
	for (j=i*16; j<nr; j++)
		printf("%02x ", buf[j]);
	if (nr%16) printf("\n");

	printf("\n");
}

int main(int argc, char *argv[])
{
	size_t n;
	des_ctx_t des;
	tdes_ctx_t tdes;
	aes_ctx_t aes;
	cipher_ctx_t ctx;
	pad_ctx_t *pad_algo = &pad_pkcs5;  /* &pad_x9p23; &pad_iso7816; &pad_zeros; */
	uint8_t  key64[] = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
	uint8_t  key3[][8] = {
		{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1},
		{0x23, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1},
		{0x43, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1}
	};
	uint8_t key256[] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};
	uint8_t iv[] = {/* iv len = blk_ctx->blklen - 4*8, it is 12 bytes for aes-ctr */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
	};
	uint8_t vect[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, /*0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 */
	};

	uint8_t buf[512];

	printf("input data:\n");
	printbuf(vect, sizeof(vect));
	memcpy(buf, vect, sizeof(vect));

	printf("----------- AES -----------\n");
	aes_init(&aes, key256, 256);

	printf("aes-ctr mode:\n");
	ctr_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ctr_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("aes-ofb mode:\n");
	ofb_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ofb_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("aes-cfb mode:\n");
	cfb_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	cfb_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("aes-cbc mode:\n");
	cbc_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	cbc_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("aes-ecb mode:\n");
	ecb_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ecb_init(&ctx, (blk_ctx_t *)&aes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("----------- DES -----------\n");
	des_init(&des, key64);

	printf("des-ctr mode:\n");
	ctr_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ctr_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("des-ofb mode:\n");
	ofb_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ofb_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("des-cfb mode:\n");
	cfb_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	cfb_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("des-cbc mode:\n");
	cbc_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	cbc_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("des-ecb mode:\n");
	ecb_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ecb_init(&ctx, (blk_ctx_t *)&des, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("-----------3DES -----------\n");
	tdes_init(&tdes, (uint8_t *)key3, 192);

	printf("3des-ctr mode:\n");
	ctr_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ctr_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("3des-ofb mode:\n");
	ofb_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ofb_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("3des-cfb mode:\n");
	cfb_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	cfb_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("3des-cbc mode:\n");
	cbc_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	cbc_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	printf("3des-ecb mode:\n");
	ecb_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.encrypt(&ctx, buf, sizeof(vect));
	printbuf(buf, n);
	ecb_init(&ctx, (blk_ctx_t *)&tdes, pad_algo, iv);
	n = ctx.decrypt(&ctx, buf, n);
	printbuf(buf, n);

	return 0;
}

