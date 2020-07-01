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
#include "hmac.h"

/*
 * test vectors from:
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA1.pdf
 */

int main(int argc, char *argv[])
{
	hmac_ctx_t hmac;
	int hash_id, len, klen, tlen, mlen, line;
	uint32_t value;
	FILE *fp;
	char *filename = "downloads/hmactestvectors/HMAC.rsp";
	uint8_t key[256];
	uint8_t tag[64], mac[64];
	uint8_t msg[512];
	uint8_t buf[1024];

	line = 0;
	printf("process file: %s\n", filename);
	fp = fopen(filename, "r");
	assert(fp);
	while (!feof(fp)) {
		value = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			line++;
			strtok(buf, "\r\n");
			if (strstr(buf, "Klen = ")) {value|=0x01;klen=atoi(buf+7);}
			else if (strstr(buf, "Tlen = ")) {value|=0x02;klen=atoi(buf+7);}
			else if (strstr(buf, "Key = ")) {value|=0x04;hex2ba(buf+6, key, sizeof(key));}
			else if (strstr(buf, "Msg = ")) {value|=0x08;mlen=strlen(buf+6)/2;hex2ba(buf+6, msg, sizeof(msg));}
			else if (strstr(buf, "Mac = "))  {value|=0x10;hex2ba(buf+6, mac, sizeof(mac));}
			else if (strlen(buf) <= 2 && value == 0x1F) break; /* \r\n */
			else if (strstr(buf, "[L="))   {
				len = atoi(buf+3);
				switch(len) {
					case 20: hash_id = eHASH_SHA1;   break;
					case 28: hash_id = eHASH_SHA224; break;
					case 32: hash_id = eHASH_SHA256; break;
					case 48: hash_id = eHASH_SHA384; break;
					case 64: hash_id = eHASH_SHA512; break;
				}
			}
		}
		if (value != 0x1F) break; /* end of file */

		assert(mlen <= sizeof(msg));

		hmac_init(&hmac, key, klen, hash_id);
		hmac.update(&hmac, msg, mlen);
		hmac.final(&hmac, tag);
		if (memcmp(tag, mac, tlen)) {
			fclose(fp);
			printf("failed at line %d of file %s\n", line, filename);
			exit(-1);
		}
	}
	fclose(fp);

	printf("ALL HMAC TESTS PASSED!\n");
	return 0;
}

