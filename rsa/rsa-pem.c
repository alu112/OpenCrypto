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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "base64.h"
#include "rsa.h"
#include "rsa-pem.h"

/* https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem */
/* https://en.wikipedia.org/wiki/X.690#DER_encoding */

/* the following multibyte value are big-endian */
static uint8_t sequence[] = {
	0x30, /* type: SEQUENCE */
	0x82, /* length: Definite, Long form, 2 length octets follows */
	0x04, 0xa4, /* the real length value */
};

static uint8_t bitstring[] = {
	0x03, /* type: BIT STRING */
	0x82, /* length: Definite, Long form, 2 length octets follows */
	0x01, 0x0f, /* the real length value */
	0x00        /* string terminator '\0' of the following bit string*/
};

#if 0
static uint8_t integer[] = {
	0x02, /* type: INTEGER */
	0x03, /* length: Definite, short form */
	0x01, 0x00, 0x01 /* 65537 */
};
#endif

static uint8_t rsa_oidnul[] = {
	0x30, /* type: SEQUENCE */
	0x0d, /* length: Definite, short form */
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, /* OID */
	0x05, 0x00 /* NULL */
};

static uint8_t pem_pkcs1hdr[] = {"-----BEGIN RSA PRIVATE KEY-----\n"};
static uint8_t pem_pkcs1ftr[] = {"-----END RSA PRIVATE KEY-----\n"};
static uint8_t pem_pkcs8hdr[] = {"-----BEGIN PUBLIC KEY-----\n"};
static uint8_t pem_pkcs8ftr[] = {"-----END PUBLIC KEY-----\n"};

#if 0
/* public key: pkcs8 */
SEQUENCE                               // PublicKeyInfo
	+- SEQUENCE                    // AlgorithmIdentifier
		+- OID                 // 1.2.840.113549.1.1.1
		+- NULL                // Optional Parameters
	+- BITSTRING                   // PublicKey
		+- SEQUENCE            // RSAPublicKey
			+- INTEGER(N)  // N
			+- INTEGER(E)  // E

/* public and the private key pair: pkcs1 */
SEQUENCE                               // PrivateKeyInfo
	+- INTEGER(0)                  // Version - v1998(0)
	+- INTEGER(N)                  // N
	+- INTEGER(E)                  // E
	+- INTEGER(D)                  // D
	+- INTEGER(P)                  // P
	+- INTEGER(Q)                  // Q
	+- INTEGER(DP)                 // d mod p-1
	+- INTEGER(DQ)                 // d mod q-1
	+- INTEGER(Inv Q)              // INV(q) mod p
#endif

static int readpemfile(char *filename, uint8_t *pem)
{
	bool    finddat;
	uint8_t buf[80];
	FILE * fp;
	struct stat statbuf;

	if (stat(filename, &statbuf))
		return -1;
	if (statbuf.st_size < 400)
		return -1;

	finddat = false;
	fp = fopen(filename, "r");
	if (!fp) return -1;
	while(fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, pem_pkcs8hdr, 11)) {
			finddat = !finddat;
			continue;
		}
		if (!strncmp(buf, pem_pkcs8ftr, 9)) {
			finddat = !finddat;
			continue;
		}
		if (!finddat) continue;
		buf[strlen(buf)-1] = '\0'; /* remove \n */
		pem += base64_decode(buf, pem);
	}
	fclose(fp);
	return 0;
}

static int writepemfile(uint8_t *pem, char *filename)
{
	int i, len;
	FILE * fp;
	uint8_t encoded[2048];

	memset(encoded, 0, sizeof(encoded));
	len = pem[2];
	len = len << 8 | pem[3];
	len = base64_encode(pem, len + sizeof(sequence), encoded);

	fp = fopen(filename, "w+");
	if (!fp) return -1;
	/* 
	 * using PKCS8 for public key pem
	 * and   PKCS1 for private key pem
	 */
	if (len < 512) /* small pem file is public pem */
		fwrite(pem_pkcs8hdr, strlen(pem_pkcs8hdr), 1, fp);
	else
		fwrite(pem_pkcs1hdr, strlen(pem_pkcs1hdr), 1, fp);

	for (i=0; i<(len/64)*64; i+=64) {
		fwrite(&encoded[i], 64, 1, fp);
		fwrite("\n", 1, 1, fp);
	}
	fputs(&encoded[i], fp); fwrite("\n", 1, 1, fp);

	if (len < 512)
		fwrite(pem_pkcs8ftr, strlen(pem_pkcs8ftr), 1, fp);
	else
		fwrite(pem_pkcs1ftr, strlen(pem_pkcs1ftr), 1, fp);
	fclose(fp);
	return 0;
}

static void copydata(uint8_t *src, uint8_t *dst, uint16_t len)
{
	dst += len - 1;
	while (len--)
		*dst-- = *src++;
}

static int bn2pem(uint8_t type, uint16_t len, uint8_t *src, uint8_t *dst)
{
	uint16_t len1;
	
	len1 = len -1;
	while(len1 && !src[len1]) len1--;
	if (src[len1] & 0x80) len1++;
	len1++;

	*dst++ = type;
	if (len1 <= 127) {
                *dst++ = len1;
                copydata(src, dst, len1);
                return len1 + 2;
	}
	else if (len1 < 256) {
                *dst++ = 0x81;
                *dst++ = len1;
                copydata(src, dst, len1);
                return len1 + 3;
	}
	else {
                *dst++ = 0x82;
                *dst++ = (len1>>8); *dst++ = (len1 & 0xFF);
                if (len1 > len) *dst++ = 0;
                copydata(src, dst, len);
                return len1 + 4;
        }
	return 0;
}

static int pem2bn(uint8_t type, uint16_t len, uint8_t *src, uint8_t *dst)
{
        uint16_t len1;
	int offset;
	uint8_t tmp[BN_LEN*sizeof(uint32_t) + 1];

        if (src[0] != type) return 0;
	memset(tmp, 0, sizeof(tmp));
	len1 = src[1];
	switch(len1) {
		case 0x81:
			len1 = src[2];
			offset = 3;
			break;
		case 0x82:
			len1 = src[2]<<8 | src[3];
			offset = 4;
			break;
		default:
			offset = 2;
			break;
	}
	copydata(src+offset, tmp, len1);
	memcpy(dst, tmp, len);
	return len1 + offset;
}

/* https://tools.ietf.org/html/rfc5915 */
/* https://tools.ietf.org/html/rfc3447#appendix-A.1.2 (PKCS #1) */
int rsa_prvkey2pem(rsa_key_t * rsa, char *pemfilename)
{
	int i, len;
	uint8_t *ppem;
	uint8_t pem[1200]; /* big enough for RSA-2048 openssl compatible format */

	memset(pem, 0, sizeof(pem));

	ppem = pem;
	memcpy(ppem, sequence, sizeof(sequence)); ppem += sizeof(sequence);
	/* version */
	i = 0;
	ppem += bn2pem(TYPE_INTEGER,     1, (uint8_t *)&i, ppem);

	ppem += bn2pem(TYPE_INTEGER, 0x100, (uint8_t *)rsa->n, ppem);
	ppem += bn2pem(TYPE_INTEGER,     3, (uint8_t *)rsa->e, ppem);
	ppem += bn2pem(TYPE_INTEGER, 0x100, (uint8_t *)rsa->d, ppem);
	ppem += bn2pem(TYPE_INTEGER,  0x80, (uint8_t *)rsa->p, ppem);
	ppem += bn2pem(TYPE_INTEGER,  0x80, (uint8_t *)rsa->q, ppem);
	ppem += bn2pem(TYPE_INTEGER,  0x80, (uint8_t *)rsa->dp, ppem);
	ppem += bn2pem(TYPE_INTEGER,  0x80, (uint8_t *)rsa->dq, ppem);
	ppem += bn2pem(TYPE_INTEGER,  0x80, (uint8_t *)rsa->invq, ppem);

	len = ppem - pem - sizeof(sequence);
	/* the length following sequence */
	pem[2] = (len >> 8) & 0xFF; pem[3] = len & 0xFF;

	return writepemfile(pem, pemfilename);
}

int rsa_pem2prvkey(char *pemfilename, rsa_key_t *rsa)
{
	uint8_t *ppem;
	uint8_t pem[1200]; /* big enough for RSA-2048 openssl compatible format */

	if (readpemfile(pemfilename, pem)) return -1;

	ppem = pem + 4 + 3;
	ppem += pem2bn(TYPE_INTEGER, 0x100, ppem, (uint8_t *)rsa->n);
	ppem += pem2bn(TYPE_INTEGER,     3, ppem, (uint8_t *)rsa->e);
	ppem += pem2bn(TYPE_INTEGER, 0x100, ppem, (uint8_t *)rsa->d);
	ppem += pem2bn(TYPE_INTEGER,  0x80, ppem, (uint8_t *)rsa->p);
	ppem += pem2bn(TYPE_INTEGER,  0x80, ppem, (uint8_t *)rsa->q);
	ppem += pem2bn(TYPE_INTEGER,  0x80, ppem, (uint8_t *)rsa->dp);
	ppem += pem2bn(TYPE_INTEGER,  0x80, ppem, (uint8_t *)rsa->dq);
	ppem += pem2bn(TYPE_INTEGER,  0x80, ppem, (uint8_t *)rsa->invq);
	rsa->keybits = 2048;
	return 0;
}

int rsa_pubkey2pem(rsa_key_t *rsa, char* pemfilename)
{
	int  len;
	uint8_t *ppem;
	uint8_t pem[1200]; /* big enough for RSA-2048 openssl compatible format */

	memset(pem, 0, sizeof(pem));

	ppem = pem;
	memcpy(ppem, sequence, sizeof(sequence)); ppem += sizeof(sequence);
	memcpy(ppem, rsa_oidnul, sizeof(rsa_oidnul)); ppem += sizeof(rsa_oidnul);
	memcpy(ppem, bitstring, sizeof(bitstring)); ppem += sizeof(bitstring);
	memcpy(ppem, sequence, sizeof(sequence)); ppem += sizeof(sequence);

	ppem += bn2pem(TYPE_INTEGER, 0x100, (uint8_t *)rsa->n, ppem);
	ppem += bn2pem(TYPE_INTEGER,     3, (uint8_t *)rsa->e, ppem);

	/* fix the length of first sequence */
	len = ppem - pem - sizeof(sequence);
	/* the length following sequence */
	pem[2] = (len >> 8) & 0xFF; pem[3] = len & 0xFF;

	/* fix the length of bitstring */
#define BITSTRING_OFFSET (sizeof(sequence) + sizeof(rsa_oidnul))
	len = ppem - pem - BITSTRING_OFFSET - sizeof(bitstring) + 1; /* the '\0' in bitstring */
	pem[BITSTRING_OFFSET + 2] = (len >> 8) & 0xFF; pem[BITSTRING_OFFSET + 3] = len & 0xFF;

	/* fix the length of second sequence */
#define SEQUENCE2_OFFSET (BITSTRING_OFFSET + sizeof(bitstring))
	len -= sizeof(sequence) + 1; /* the '\0 in bitstring */
	pem[SEQUENCE2_OFFSET + 2]  = (len >> 8) & 0xFF; pem[SEQUENCE2_OFFSET + 3] = len & 0xFF;

	return writepemfile(pem, pemfilename);
}


int rsa_pem2pubkey(char *pemfilename, rsa_key_t *rsa)
{
	uint8_t *ppem;
	uint8_t pem[1200]; /* big enough for RSA-2048 openssl compatible format */

	if (readpemfile(pemfilename, pem)) return -1;

#define RSA_OIDNUL_OFFSET (sizeof(sequence))

	if (memcmp(pem + RSA_OIDNUL_OFFSET, rsa_oidnul, sizeof(rsa_oidnul))) return -1;
#define RSA_N_OFFSET (SEQUENCE2_OFFSET + sizeof(sequence))
	ppem = pem + RSA_N_OFFSET;
	ppem += pem2bn(TYPE_INTEGER, 0x100, ppem, (uint8_t *)rsa->n);
	ppem += pem2bn(TYPE_INTEGER,     3, ppem, (uint8_t *)rsa->e);
	rsa->keybits = 2048;
	return 0;

}

