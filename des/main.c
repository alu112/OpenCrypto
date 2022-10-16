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
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "des.h"

/*
 * usage:
 * des 0x1234567890abcdef 0x48656c6c6f576f72
 */

/*
 * openssl enc -des-cbc -e -in des-in.bin -out des-encrypt.bin -K 133457799bbcdff1 -iv 0 -nopad
 * openssl enc -des-cbc -d -in des-encrypt.bin -out des-decrypt.bin -K 133457799bbcdff1 -iv 0 -nopad
 * hexdump -C des-in.bin
 * hexdump -C des-encrypt.bin
 * hexdump -C des-decrypt.bin
 */

void print_block(char *msg, uint8_t *blk)
{
	int i;
	uint8_t *p8 = (uint8_t *)blk;

	printf("%s", msg);
	for (i=0; i<8; i++)
		printf("%02x ", *p8++);
	printf("\n");
}

int main(int argc, char *argv[])
{
	des_ctx_t ctx;
	int      n, fd;
	uint8_t  key64[] = {0x4c, 0x73, 0xab, 0xe6, 0x9b, 0xbc, 0xfe, 0xf1};
	uint8_t  data64[] = {0xd2, 0xc3, 0x5d, 0x12, 0x87, 0xd4, 0x60, 0xee};
	uint8_t  cipher64[8] = { 0 };
	uint8_t  blk64[8];

	memcpy(blk64, data64, 8);
	/* create a input file */
	fd = open("des-in.bin", O_WRONLY | O_CREAT, 0644);
	n = write(fd, blk64, sizeof(blk64));
	close(fd);

	//key64 = 0x133457799bbcdff1;
	print_block("\nkey64 =", key64);
	print_block("data  =", data64);

	printf("--------- ENCRYPTION ---------\n");
	fd = open("des-in.bin", O_RDONLY);
	n = read(fd, blk64, sizeof(blk64));
	close(fd);
	assert(n>=8); 
	print_block("block =", blk64);
	des_init(&ctx, key64);
	ctx.encrypt(&ctx, blk64, 1);
	print_block("cipher=", blk64);
	memcpy(cipher64, blk64, 8);
	if (memcmp(blk64, cipher64, 8)) printf("DES encrypt FAILED\n");
	else printf("DES encrypt SUCCEEDED\n");
	fd = open("des-encrypt.bin", O_WRONLY | O_CREAT, 0644);
	n = write(fd, blk64, sizeof(uint64_t));
	close(fd);

	printf("--------- DECRYPTION ---------\n");
	fd = open("des-encrypt.bin", O_RDONLY);
	n = read(fd, blk64, sizeof(blk64));
	close(fd);
	print_block("cipher=", blk64);
	ctx.decrypt(&ctx, blk64, 1);
	print_block("block =", blk64);
	if (memcmp(blk64, data64, 8)) printf("DES decrypt FAILED\n");
	else printf("DES decrypt SUCCEEDED\n");
	fd = open("des-decrypt.bin", O_WRONLY | O_CREAT, 0644);
	n = write(fd, blk64, sizeof(uint64_t));
	close(fd);
	return 0;
}

