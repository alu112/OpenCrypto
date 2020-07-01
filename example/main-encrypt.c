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
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <termios.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bn.h"
#include "sha256.h"
#include "cipher-mode.h"
#include "aes.h"
#include "base64.h"


int usage(char * fname)
{
	printf("Usage: %s [-e  | -d] filename\n", fname);
	return 1;
}

int main(int argc, char *argv[])
{
	int rc, op, c;
	size_t fsize, wsize;
	struct stat statbuf;
	sha256_ctx_t sha;
	aes_ctx_t aes;
	cipher_ctx_t ctr;
	pad_ctx_t *pad = &pad_pkcs5;
	uint8_t *passwd, *buf, *tempbuf;
	uint8_t digest[SHA_DIGEST_LENGTH / 8];
	uint8_t iv[] = {"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"};
	FILE *fp;
	char *filename;

	static struct option long_options[] = {
		{"encrypt", 0, NULL,  'e'},
		{"decrypt", 0, NULL,  'd'},
		{0        , 0, 0   , 0  }
	};
	int long_index = 0;


	while((c = getopt_long(argc, argv, "ed", long_options, &long_index)) != -1)
	{
		switch (c) {
			case 'e':
			case 'd':
				op = c;
				break;
			default:
				return usage(argv[0]);
		}
	}
	if (optind < argc) {
		filename = argv[optind];
	}
	else {
		return usage(argv[0]);
	}

	/* get file size and allocate memory*/
	rc = stat(filename, &statbuf);
	if (rc) {
		printf("Failed to get file size of %s\n", filename);
		return -1;
	}
	fsize = statbuf.st_size;
	buf = malloc(fsize*2);
	tempbuf = malloc(fsize*2);
	if (!buf || !tempbuf) {
		printf("memory alloc fails\n");
		if (buf) free(buf);
		if (tempbuf) free(tempbuf);
		return -1;
	}
	/* open, read, close file, fsize*2 is more than enough to hold file content and temp data */
	memset(buf, 0, fsize*2);
	fp = fopen(filename, "r");
	rc = fread(buf, fsize, 1, fp);
	fclose(fp);

	if (1 != rc) {
		printf("entire read fails\n");
		return -1;
	}


	/* obtain key */
	passwd = getpass("Enter password: ");

	/* hash key */
	sha256_init(&sha);
	sha.init(&sha);
	sha.update(&sha, passwd, strlen(passwd));
	sha.final(&sha, digest);
	memset(passwd, 0, strlen(passwd));

	/* initialize  hash and aes */
	aes_init(&aes, digest, sha.md_len);
	memset(digest, 0, sizeof(digest));
	ctr_init(&ctr,(blk_ctx_t *)&aes , pad, iv);

	if(op == 'e') {
		wsize = ctr.encrypt(&ctr, buf, fsize);
		memcpy(tempbuf, buf, wsize);
		wsize = base64_encode(tempbuf, wsize, buf);
		wsize--;
		memset(tempbuf, 0, fsize*2);
	}
	else{
		wsize = base64_decode(buf, buf);
		wsize = ctr.decrypt(&ctr, buf, wsize);
	}
	memset(&aes, 0, sizeof(aes));
	memset(&ctr, 0, sizeof(ctr));

	/* write to file */
	fp = fopen(filename, "w");
	fwrite(buf, wsize, sizeof(uint8_t), fp);
	fclose(fp);
	memset(buf, 0, fsize*2);
	free(buf);
	free(tempbuf);

	return 0;
}

