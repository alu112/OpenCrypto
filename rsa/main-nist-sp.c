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

/* The RSASP1 Signature Primitive Validation System (RSASP1VS) */
/* SP: Signature Primitive */

int main(int argc, char *argv[])
{
	int line, value;
	FILE *fp;
	char *filename = "downloads/RSA2SP1testvectors/RSASP1.fax";
	uint8_t buf[1024];
	rsa_key_t prv, pub;
	int emlen, slen;
	uint8_t sign[256], em[256], out[256];
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
			else if (strstr(buf, "p = ")) {value|=0x02;bn_hex2bn(buf+4, prv.p);}
			else if (strstr(buf, "q = ")) {value|=0x04;bn_hex2bn(buf+4, prv.q);}
			else if (strstr(buf, "e = ")) {value|=0x08;bn_hex2bn(buf+4, prv.e);}
			else if (strstr(buf, "d = ")) {value|=0x10;bn_hex2bn(buf+4, prv.d);}
			else if (strstr(buf, "EM = ")) {value|=0x20;emlen=hex2ba(buf+5, em, sizeof(em));}
			else if (strstr(buf, "S = ")) {
				value|=0x40;
				if (!strncmp(buf+4,"FAIL", 4)) 
					result=1; 
				else 
					slen=hex2ba(buf+4, sign, sizeof(sign));
			}
			else if (strlen(buf) <= 2 && value == 0x7F) break; /* \r\n */
		}
		if (value != 0x7F) break; /* end of file */
		/* signature generation */
		rc = rsa_sign(&prv, em, emlen, out);
		if (rc) {
			if (!result) {
				fclose(fp);
				printf("decrypt failed at line %d of file %s\n", line, filename);
				exit(-1);
			}
		}
		else if (memcmp(sign, out, slen)) {
			fclose(fp);
			printf("decrypt msg doesn't match at line %d of file %s\n", line, filename);
			exit(-1);
		}
		else printf("%d OK\n", line);

		/* signature verification */
		if (result) continue;
		memset(&pub, 0, sizeof(pub));
		pub.keybits = prv.keybits;
		bn_cpy(prv.n, pub.n);
		bn_cpy(prv.e, pub.e);

		rc = rsa_verify(&pub, sign, slen, out);
		if (rc) {
			fclose(fp);
			printf("decrypt msg doesn't match at line %d of file %s\n", line, filename);
			exit(-1);
		}
		else {
			if (memcmp(em, out, emlen)) {
				printf("signature verification failed at line %d of file %s\n", line, filename);
				exit(-1);
			}
			else
				printf("%d OK\n", line);
		}
	}
	fclose(fp);

	printf("ALL RSA Signature Primitive TESTS PASSED!\n");

	return 0;
}

