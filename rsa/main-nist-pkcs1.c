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
#include "rsassa-pkcs1.h"


/* 186-3 RSA Test Vectors for PKCS1 v1.5
 */ 


enum hash_id str2hash_id(char *name)
{
	int i;
	struct s2e {
		char hash_algo[16];
		enum hash_id hash_id;
	} hashes[] = {
		{ "SHA1",      eHASH_SHA1 },
		{ "SHA224",    eHASH_SHA224 },
		{ "SHA256",    eHASH_SHA256 },
		{ "SHA384",    eHASH_SHA384 },
		{ "SHA512",    eHASH_SHA512 },
		{ "SHA512224", eHASH_SHA512_224 },
		{ "SHA512256", eHASH_SHA512_256 },
		{ "SHA3_224",  eHASH_SHA3_224 },
		{ "SHA3_256",  eHASH_SHA3_256 },
		{ "SHA3_384",  eHASH_SHA3_384 },
		{ "SHA3_512",  eHASH_SHA3_512 }

	};
	for (i=0; i<ARRAY_SIZE(hashes); i++)
		if (!strcmp(name, hashes[i].hash_algo))
			return hashes[i].hash_id;
	return -1;
}

int sig_gen(char *filename)
{
	int line, value;
	FILE *fp;
	uint8_t buf[4096];
	rsa_key_t prv;
	int signlen, slen, mlen, nbits;
	uint8_t sign[512], msg[512], em[512], out[512];
	int rc=0;
	char sha_name[16];
	rsassa_pkcs1_ctx_t ctx;
	enum hash_id hash_id;

	line = 0;
	memset(sign,0, sizeof(sign));
	memset(msg, 0, sizeof(msg));
	memset(em,  0, sizeof(em));
	memset(out, 0, sizeof(out));
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
			else if (strstr(buf, "n = ")) {bn_hex2bn(buf+4, prv.n);}
			else if (strstr(buf, "e = ")) {bn_hex2bn(buf+4, prv.e);}
			else if (strstr(buf, "d = ")) {bn_hex2bn(buf+4, prv.d);}
			else if (strstr(buf, "SHAAlg = ")) {value|=0x01;strcpy(sha_name, buf+9);}
			else if (strstr(buf, "Msg = ")) {value|=0x2;mlen=hex2ba(buf+6, msg, sizeof(msg));}
			else if (strstr(buf, "S = ")) {value|=0x4;signlen=hex2ba(buf+4, sign, sizeof(sign));}
			else if (strlen(buf) <= 2 && value == 0x7) break; /* \r\n */
		}
		if (value != 0x7) break; /* end of file */

		/* signature generation */
		nbits = bn_getmsbposn(prv.n);
		hash_id = str2hash_id(sha_name);

		rc |= rsassa_pkcs1_init(&ctx, nbits-1, hash_id);
		rc |= ctx.encodepad(&ctx, mlen, msg, slen, em);
		rc |= rsa_sign(&prv, em, prv.keybits/8, out);

		if (rc) {
			fclose(fp);
			printf("signature generatoin FAILED at line %d of file %s\n", line, filename);
			exit(-1);
		}
		else if (memcmp(sign, out, signlen)) {
			fclose(fp);
			printf("signature doesn't match at line %d of file %s\n", line, filename);
			exit(-1);
		}
		else {
			printf("."); fflush(stdout);
			//printf("%d OK\n", line);
		}
	}
	fclose(fp);

	printf("ALL RSA Signature Generation TESTS PASSED!\n");

	return 0;
}

int sig_verify(char *filename)
{
	int line, value;
	FILE *fp;
	uint8_t buf[4096];
	rsa_key_t pub;
	int emlen, mlen, signlen, slen, nbits;
	uint8_t sign[512], em[512], out[512], msg[512];
	int rc, result=0;
	char sha_name[16];
	rsassa_pkcs1_ctx_t ctx;
	enum hash_id hash_id;

	line = 0;
	memset(sign,0, sizeof(sign));
	memset(msg, 0, sizeof(msg));
	memset(em,  0, sizeof(em));
	memset(out, 0, sizeof(out));
	memset(&pub, 0, sizeof(pub));
	printf("process file: %s\n", filename);
	fp = fopen(filename, "r");
	assert(fp);
	while (!feof(fp)) {
		value = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			line++;
			strtok(buf, "\r\n");
			if (strstr(buf, "[mod = ")) {pub.keybits=atoi(buf+6);}
			else if (strstr(buf, "n = ")) {bn_hex2bn(buf+4, pub.n);}
			else if (strstr(buf, "p = ")) {bn_hex2bn(buf+4, pub.p);}
			else if (strstr(buf, "q = ")) {bn_hex2bn(buf+4, pub.q);}
			else if (strstr(buf, "SHAAlg = ")) {value|=0x01;strcpy(sha_name, buf+9);}
			else if (strstr(buf, "e = ")) {value|=0x2;bn_hex2bn(buf+4, pub.e);}
			else if (strstr(buf, "d = ")) {value|=0x4;bn_hex2bn(buf+4, pub.d);}
			else if (strstr(buf, "Msg = ")) {value|=0x8;mlen=hex2ba(buf+6, msg, sizeof(msg));}
			else if (strstr(buf, "S = ")) {value|=0x10;signlen=hex2ba(buf+4, sign, sizeof(sign));}
			else if (strstr(buf, "Result = ")) {value|=0x20;result=buf[9]=='P'?0:-1;}
			else if (strlen(buf) <= 2 && value == 0x3F) break; /* \r\n */
		}
		if (value != 0x3F) break; /* end of file */

		/* signature verification */
		nbits = bn_getmsbposn(pub.n);
		hash_id = str2hash_id(sha_name);

		rc = rsassa_pkcs1_init(&ctx, nbits-1, hash_id);
		if (rc) printf("rsassa_pss_init FAILED at line %d of file %s\n", line, filename);
		emlen = ctx.k;
		rc = rsa_verify(&pub, sign, signlen, em);
		if (rc) printf("rsa verify FAILED at line %d of file %s\n", line, filename);
		rc = ctx.decodepad(&ctx, mlen, msg, slen, emlen, em);
		if (rc) {
			if (!result) {
				fclose(fp);
				printf("rsa verify decode failed at line %d of file %s\n", line, filename);
				exit(-1);
			}
		}
		else {
			printf("."); fflush(stdout);
			//printf("%d OK\n", line);
		}
	}
	fclose(fp);

	printf("ALL RSA Signature Verification TESTS PASSED!\n");

	return 0;
}

int main(int argc, char *argv[])
{
	int i, rc=0;
	char sign_gen_filename[][128] = {
		"downloads/186-2rsatestvectors/SigGen15_186-2.txt",
		"downloads/186-3rsatestvectors/SigGen15_186-3.txt",
		"downloads/186-3rsatestvectors/SigGen15_186-3_TruncatedSHAs.txt",
	};
	char sign_ver_filename[][128] = {
		"downloads/186-2rsatestvectors/SigVer15_186-3.rsp",
		"downloads/186-3rsatestvectors/SigVer15_186-3.rsp",
		"downloads/186-3rsatestvectors/SigVer15_186-3_TruncatedSHAs.rsp",
	};

	if (4096 > MAXBITLEN) {
		printf("this test has to be compiled with:\n"
			"make clean; make CPPFLAGS=\"-DMAXBITLEN=4096\"\n"); 
		exit(-1);
	}
	for (i=0; i<ARRAY_SIZE(sign_gen_filename); i++) {
		rc = sig_gen(sign_gen_filename[i]);
		if (rc) return rc;
	}
	for (i=0; i<ARRAY_SIZE(sign_ver_filename); i++) {
		rc = sig_verify(sign_ver_filename[0]);
		if (rc) return rc;
	}
	return 0;
}

