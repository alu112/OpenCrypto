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
#include "bn.h"
#include "ec-gfp.h"
#include "ec-gf2m.h"
#include "ec-param.h"
#include "sha-common.h"

/* The Elliptic Curve Primitive Component Validation */
/* DP: Decryption Primitive */

int get_curvename(char *key_id, char *name)
{
	int rc = 0;


	name[0] = '\0';
	if (!strcmp(key_id, "P-192")) strcpy(name, "prime192v1");
	else if (!strcmp(key_id, "P-224")) strcpy(name, "secp224r1");
	else if (!strcmp(key_id, "P-256")) strcpy(name, "prime256v1");
	else if (!strcmp(key_id, "P-384")) strcpy(name, "secp384r1");
	else if (!strcmp(key_id, "P-521")) strcpy(name, "secp521r1");
	else if (!strcmp(key_id, "K-163")) strcpy(name, "sect163k1");
	else if (!strcmp(key_id, "K-233")) strcpy(name, "sect233k1");
	else if (!strcmp(key_id, "K-283")) strcpy(name, "sect283k1");
	else if (!strcmp(key_id, "K-409")) strcpy(name, "sect409k1");
	else if (!strcmp(key_id, "K-571")) strcpy(name, "sect571k1");
	else if (!strcmp(key_id, "B-163")) strcpy(name, "sect163r2");
	else if (!strcmp(key_id, "B-233")) strcpy(name, "sect233r1");
	else if (!strcmp(key_id, "B-283")) strcpy(name, "sect283r1");
	else if (!strcmp(key_id, "B-409")) strcpy(name, "sect409r1");
	else if (!strcmp(key_id, "B-571")) strcpy(name, "sect571r1");
	else rc = -1;

	if (strlen(name) == 0) rc = -1;
	printf("%s\n", name);
	return rc;
}

int main(int argc, char *argv[])
{
	int line, value;
	FILE *fp;
	//char *filename = "downloads/186-2ecdsatestvectors/KeyPair.rsp";
	char *filename = "downloads/186-4ecdsatestvectors/KeyPair.rsp";
	uint8_t buf[1024];
	int len;
	char curve_name[64], CK;
	ec_keyblob_t keys, key_v;

	line = 0;
	memset(&keys, 0, sizeof(keys));
	memset(&key_v, 0, sizeof(key_v));
	printf("process file: %s\n", filename);
	fp = fopen(filename, "r");
	assert(fp);
	while (!feof(fp)) {
		value &= 1;
		while (fgets(buf, sizeof(buf), fp)) {
			line++;
			strtok(buf, "\r\n");
			if (strstr(buf, "[P-")) {printf("%s: ", buf);CK='P';buf[6]=0;if (get_curvename(&buf[1], curve_name)) value=0; else value=1;}
			else if (strstr(buf, "[K-")) {printf("%s: ", buf);CK='K';buf[6]=0;if (get_curvename(&buf[1], curve_name)) value=0; else value=1;}
			else if (strstr(buf, "[B-")) {printf("%s: ", buf);CK='B';buf[6]=0;if (get_curvename(&buf[1], curve_name)) value=0; else value=1;}
			else if (strstr(buf, "d = ")) {value|=0x02;bn_hex2bn(buf+4, keys.private);}
			else if (strstr(buf, "Qx = ")) {value|=0x04;bn_hex2bn(buf+5, key_v.public.x);}
			else if (strstr(buf, "Qy = ")) {value|=0x08;bn_hex2bn(buf+5, key_v.public.y);}
			else if (strlen(buf) <= 2 && value == 0x0F) break; /* \r\n */
		}
		if (value != 0x0F) break; /* end of file */

		//ec_keygen_gfX(curve_name, &keys);
		/* this is a copy of ec_keygen_gfp() */
		len = ec_getcurve(curve_name, &keys.ec);
		if (len > 0) {
			//bn_gen_random(keys->ec.keylen, keys->private);
			switch(CK) {
				case 'P':
					gfp_mulmod(&keys.ec.g, keys.private, &keys.ec, &keys.public);
					break;
				case 'K':
					gf2m_mulmod(&keys.ec.g, keys.private, &keys.ec, &keys.public);
					break;
				case 'B':
				default:
					break;
			}
		}
		if (gfp_isequal(&keys.public, &key_v.public))
			printf("EC-GFP KeyGen @ line=%d SUCCEEDED\n", line);
		else {
			printf("EC-GFP KeyGen @ line=%d FAILED\n", line);
			fclose(fp);
			return (-1);
		}
	}
	fclose(fp);

	printf("ALL RSA Decrypt Primitive TESTS PASSED!\n");

	return 0;
}

