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
#include "rsa.h"
#include "sha-common.h"

/* The RSADP Primitive Component Validation System (RSADPVS) */
/* DP: Decryption Primitive */

int main(int argc, char *argv[])
{
	int line, value;
	FILE *fp;
	char *filename = "downloads/RSADPtestvectors/RSADPComponent800_56B.txt";
	uint8_t buf[1024];
	rsa_key_t prv, pub;
	int clen, mlen;
	uint8_t cipher[256];
	uint8_t msg[256], out[256];
	int rc, result=0;

	line = 0;
	memset(&prv, 0, sizeof(prv));
	printf("process file: %s\n", filename);
	fp = fopen(filename, "r");
	assert(fp);
	while (!feof(fp)) {
		value = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			line++;
			strtok(buf, "\r\n");
			if (strstr(buf, "[mod = ")) {prv.keybits=atoi(buf+6);}
			else if (strstr(buf, "n = ")) {value|=0x01;bn_hex2bn(buf+4, prv.n);}
			else if (strstr(buf, "e = ")) {value|=0x02;bn_hex2bn(buf+4, prv.e);}
			else if (strstr(buf, "d = ")) {value|=0x02;bn_hex2bn(buf+4, prv.d);}
			else if (strstr(buf, "c = ")) {value|=0x04;clen=hex2ba(buf+4, cipher, sizeof(cipher));}
			else if (strstr(buf, "Result = "))  {value|=0x08;result=strcmp(buf+9, "Pass");value|= result?0:0x10;}
			else if (strstr(buf, "k = ")) {value|=0x10;mlen=hex2ba(buf+4, msg, sizeof(msg));}
			else if (strlen(buf) <= 2 && value == 0x1F) break; /* \r\n */
		}
		if (value != 0x1F) break; /* end of file */

		/* decrypt */
		rc = rsa_decrypt(&prv, cipher, clen, out);
		if (rc) {
			if (!result) {
				fclose(fp);
				printf("decrypt failed at line %d of file %s\n", line, filename);
				exit(-1);
			}
		}
		else if (memcmp(msg, out, mlen)) {
			fclose(fp);
			printf("decrypt msg doesn't match at line %d of file %s\n", line, filename);
			exit(-1);
		}
		else printf("decrypt mlen=%d, line %d OK\n", mlen, line);

		/* encrypt */
		if (result) continue;
		memset(&pub, 0, sizeof(pub));
		pub.keybits = prv.keybits;
		bn_cpy(prv.n, pub.n);
		bn_cpy(prv.e, pub.e);

		rc = rsa_encrypt(&pub, msg, mlen, out);
		if (rc || memcmp(cipher, out, clen)) {
			fclose(fp);
			printf("encrypt msg doesn't match at line %d of file %s\n", line, filename);
			exit(-1);
		}
		//else printf("encrypt clen=%d, line %d OK\n", clen, line);
	}
	fclose(fp);

	printf("ALL RSA Decrypt Primitive TESTS PASSED!\n");

	return 0;
}

