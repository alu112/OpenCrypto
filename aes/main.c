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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "aes.h"

/*
 * openssl enc -aes-128-cbc -e -in aes-in.bin -out aes-encrypt.bin -K 2b7e151628aed2a6abf7158809cf4f3c -iv 0 -nopad
 * openssl enc -aes-128-cbc -d -in aes-encrypt.bin -out aes-decrypt.bin -K 2b7e151628aed2a6abf7158809cf4f3c -iv 0 -nopad
 * hexdump -C aes-in.bin
 * hexdump -C aes-encrypt.bin
 * hexdump -C aes-decrypt.bin
 */
static void printblocks(uint8_t *blocks, int nr)
{
	int i, j;
	for (i=0; i<nr; i++) {
		for (j=0; j<16; j++)
			printf("%02x ", blocks[i*16+j]);
		printf("\n");
	}
	printf("\n");
}

// 512bit text
uint8_t blocks_in[64] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
uint8_t blocks_out[64];

uint8_t key256[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
uint8_t out256[] = {
	0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
};
uint8_t key192[] = {
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};
uint8_t out192[] = {
	0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc
};
uint8_t key128[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
uint8_t out128[] = {
	0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};

uint8_t in[]  = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
uint8_t test_vector[16];

int main(int argc, char *argv[])
{
	ssize_t n;
	aes_ctx_t ctx;
	/* create a input file */
	int fd = open("aes-in.bin", O_WRONLY | O_CREAT, 0644);
	n = write(fd, blocks_in, sizeof(blocks_in));
	close(fd);
	if (n != sizeof(blocks_in)) return -1;

	printf("original data:\n");
	printblocks(blocks_in, 4);
	memcpy(blocks_out, blocks_in, sizeof(blocks_in));
	aes_init(&ctx, key128, 128);
	ctx.encrypt(&ctx, blocks_out, 4);
	printf("encrypted data:\n");
	printblocks(blocks_out, 4);
	ctx.decrypt(&ctx, blocks_out, 4);
	printf("decrypted data:\n");
	printblocks(blocks_out, 4);
	if (memcmp(blocks_in, blocks_out, sizeof(blocks_in))) printf("AES-128 encrypt/decrypt failed\n");
	else printf("AES-128 encrypt/decrypt succeeded\n");

	memcpy(test_vector, in, 16);
	ctx.encrypt(&ctx, test_vector, 1);
	if (memcmp(out128, test_vector, 16)) printf("AES-128 encrypt failed\n");
	else printf("AES-128 encrypt succeeded\n");
	ctx.decrypt(&ctx, test_vector, 1);
	if (memcmp(in, test_vector, 16)) printf("AES-128 decrypt failed\n");
	else printf("AES-128 decrypt succeeded\n");

	memcpy(test_vector, in, 16);
	aes_init(&ctx, key192, 192);
	ctx.encrypt(&ctx, test_vector, 1);
	if (memcmp(out192, test_vector, 16)) printf("AES-192 encrypt failed\n");
	else printf("AES-192 encrypt succeeded\n");
	ctx.decrypt(&ctx, test_vector, 1);
	if (memcmp(in, test_vector, 16)) printf("AES-192 decrypt failed\n");
	else printf("AES-192 decrypt succeeded\n");

	memcpy(test_vector, in, 16);
	aes_init(&ctx, key256, 256);
	ctx.encrypt(&ctx, test_vector, 1);
	if (memcmp(out256, test_vector, 16)) printf("AES-256 encrypt failed\n");
	else printf("AES-256 encrypt succeeded\n");
	ctx.decrypt(&ctx, test_vector, 1);
	if (memcmp(in, test_vector, 16)) printf("AES-256 decrypt failed\n");
	else printf("AES-256 decrypt succeeded\n");


	return 0;
}

