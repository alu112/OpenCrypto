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
#include "base64.h"
#include "ec-gfp.h"
#include "ec-pem.h"


/* 
 * command to generate test PEM files:
 * openssl ecparam -name prime256v1 -genkey -out prime256v1prv.pem
 * openssl ec -in prime256v1prv.pem -pubout -out prime256v1pub.pem
 *
 * Example of PEM files:
 *
 * $ cat prime256v1prv.pem
 * -----BEGIN EC PARAMETERS-----
 * BggqhkjOPQMBBw==
 * -----END EC PARAMETERS-----
 * -----BEGIN EC PRIVATE KEY-----
 * MHcCAQEEIK0EWvLSQ6I/jSYzvPcYPNqcVRFl7y7l/tOVFNNquS7aoAoGCCqGSM49
 * AwEHoUQDQgAEGZhnI6hSHMGA10Wt2ebe6ZxTe//4lX3XI1Oc0pLjFL4B6+4YlrmG
 * 14KV2wusvjVGm3nodhH2T60axtSlRyvvWg==
 * -----END EC PRIVATE KEY-----
 *
 * $ cat prime256v1pub.pem
 * -----BEGIN PUBLIC KEY-----
 * MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGZhnI6hSHMGA10Wt2ebe6ZxTe//4
 * lX3XI1Oc0pLjFL4B6+4YlrmG14KV2wusvjVGm3nodhH2T60axtSlRyvvWg==
 * -----END PUBLIC KEY-----
 *
 */

/* https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem */
/* https://en.wikipedia.org/wiki/X.690#DER_encoding */

/* the following multibyte value are big-endian */
static uint8_t pub_sequence[] = {
	0x30, /* type: SEQUENCE */
	0x59, /* length: short form, length octet */
	0x30, /* type: SEQUENCE */
	0x13, /* length: Definite, short form */
	0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, /* OID */
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, /* OID */
	0x03, 0x42, 0x00, 0x04, /* bit string */
};

static uint8_t bitstring[] = {
	0x03, /* type: BIT STRING */
	0x42, /* length: Definite, Long form, 2 length octets follows */
	0x00, 0x04  /* string terminator '\0' of the following bit string*/
};

static uint8_t ec_oid[] = {
	0xa0, 0x0a,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, /* OID */
	0xa1, 0x44,
};

static uint8_t prv_sequence[] = {
	0x30,
	0x77,
	0x02, 0x01, 0x01,
};

static uint8_t pem_pkcs1hdr[] = {"-----BEGIN EC PRIVATE KEY-----\n"};
static uint8_t pem_pkcs1ftr[] = {"-----END EC PRIVATE KEY-----\n"};
static uint8_t pem_pkcs8hdr[] = {"-----BEGIN PUBLIC KEY-----\n"};
static uint8_t pem_pkcs8ftr[] = {"-----END PUBLIC KEY-----\n"};
static uint8_t pem_paramhdr[] = {"-----BEGIN EC PARAMETERS-----\n"};
static uint8_t pem_paramftr[] = {"-----END EC PARAMETERS-----\n"};
#if 0
/* public key: pkcs8 */
SEQUENCE                               // PublicKeyInfo
	+- SEQUENCE                    // AlgorithmIdentifier
		+- OID                 // 
		+- OID                 // 
	+- BITSTRING                   // PublicKey

/* public and the private key pair: pkcs1 */
SEQUENCE                               // PrivateKeyInfo
	+- INTEGER(1)                  // Version 1
	+- BITSTRING(prv)              // Private Key
	+- OID                         // OID1, OID2
	+- BITSTRING(pub)              // Public Key


	/* elliptic curve parameters */
	SEQUENCE

#endif

static int readpemfile(char *filename, uint8_t *pem)
{
	bool    finddat;
	uint8_t buf[80];
	FILE * fp;

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
	int i, blen, len;
	FILE * fp;
	uint8_t ecparam[32];
	uint8_t encoded[2048];
#define MAXPUBLEN 90
	memset(encoded, 0, sizeof(encoded));
	blen = pem[1];
	len = base64_encode(pem, blen + 2, encoded);

	fp = fopen(filename, "w+");
	if (!fp) return -1;
	/* 
	 * using PKCS8 for public key pem
	 * and   PKCS1 for private key pem
	 */
	if (blen < MAXPUBLEN) /* small pem file is public pem */
		fwrite(pem_pkcs8hdr, strlen(pem_pkcs8hdr), 1, fp);
	else {
		memset(ecparam, 0, sizeof(ecparam));
		(void)base64_encode(ec_oid+2, 10, ecparam);
		fwrite(pem_paramhdr, strlen(pem_paramhdr), 1, fp);
		fputs(ecparam, fp);
		fwrite("\n", 1, 1, fp);
		fwrite(pem_paramftr, strlen(pem_paramftr), 1, fp);

		fwrite(pem_pkcs1hdr, strlen(pem_pkcs1hdr), 1, fp);
	}
	for (i=0; i<(len/64)*64; i+=64) {
		fwrite(&encoded[i], 64, 1, fp);
		fwrite("\n", 1, 1, fp);
	}
	fputs(&encoded[i], fp); fwrite("\n", 1, 1, fp);

	if (blen < MAXPUBLEN)
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
	bool check = len & 0x8000 ? false : true;

	len &= ~0x8000;
	if (check) {
		if (type == TYPE_OCTSTRING) len1 = len;
		else {
			len1 = len -1;
			while(len1 && !src[len1]) len1--;
			if (src[len1] & 0x80) len1++;
			len1++;
		}
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
	}
	else {
		copydata(src, dst, len);
		return len;
	}
	return 0;
}

static int pem2bn(uint8_t type, uint16_t len, uint8_t *src, uint8_t *dst)
{
	bool check;
	int offset;
	uint16_t len1;
	uint8_t tmp[BN_LEN*sizeof(uint32_t) + 1];

	check = len & 0x8000 ? false : true;

	if (check) {
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
	else {
		len &= ~0x8000;
		copydata(src, dst, len);
		return len;
	}
	return 0;
}

/* https://tools.ietf.org/html/rfc5915 */
/* https://tools.ietf.org/html/rfc3447#appendix-A.1.2 (PKCS #1) */
int ec_pubkey2pem(ec_keyblob_t * ec, char *pemfilename)
{
	uint8_t *ppem;
	uint8_t pem[1200]; /* big enough for RSA-2048 openssl compatible format */

	memset(pem, 0, sizeof(pem));

	ppem = pem;
	memcpy(ppem, pub_sequence, sizeof(pub_sequence)); ppem += sizeof(pub_sequence);
	ppem += bn2pem(TYPE_BITSTRING,0x8020, (uint8_t *)ec->public.x, ppem);
	ppem += bn2pem(TYPE_BITSTRING,0x8020, (uint8_t *)ec->public.y, ppem);

	/* the length first sequence */
	pem[1] = ppem - pem  - 2;
	pem[24] = ppem - pem - sizeof(pub_sequence) + 2;
	return writepemfile(pem, pemfilename);
}

int ec_pem2pubkey(char *pemfilename, ec_keyblob_t *ec)
{
	uint16_t len;
	uint8_t *ppem;
	uint8_t pem[1200];

	if (readpemfile(pemfilename, pem)) return -1;

	len = (pem[24] - 2) / 2;
	ppem = pem + 27;
	ppem += pem2bn(TYPE_BITSTRING,0x8000|len, ppem, (uint8_t *)ec->public.x);
	ppem += pem2bn(TYPE_BITSTRING,0x8000|len, ppem, (uint8_t *)ec->public.y);
	return 0;
}

int ec_prvkey2pem(ec_keyblob_t *ec, char* pemfilename)
{
	uint16_t  len;
	uint8_t *ppem;
	uint8_t pem[1200]; /* big enough for RSA-2048 openssl compatible format */

	memset(pem, 0, sizeof(pem));

	ppem = pem;
	memcpy(ppem, prv_sequence, sizeof(prv_sequence)); ppem += sizeof(prv_sequence);

	ppem += bn2pem(TYPE_OCTSTRING, 0x20, (uint8_t *)ec->private, ppem);
	memcpy(ppem, ec_oid, sizeof(ec_oid)); ppem += sizeof(ec_oid);
	len = 0x20;
	bitstring[1] = len * 2 + 2;
	memcpy(ppem, bitstring, sizeof(bitstring)); ppem += sizeof(bitstring);
	len |= 0x8000;
	ppem += bn2pem(TYPE_BITSTRING, len, (uint8_t *)ec->public.x, ppem);
	ppem += bn2pem(TYPE_BITSTRING, len, (uint8_t *)ec->public.y, ppem);

	/* the length first sequence */
	pem[1] = ppem -pem - 2;

	return writepemfile(pem, pemfilename);
}


int ec_pem2prvkey(char *pemfilename, ec_keyblob_t *ec)
{
	int posn;
	uint16_t len;
	uint8_t *ppem;
	uint8_t pem[1200]; /* big enough for RSA-2048 openssl compatible format */

	if (readpemfile(pemfilename, pem)) return -1;

	if (memcmp(pem, ec_oid + 2, sizeof(ec_oid)-4)) return -1;
	posn = sizeof(ec_oid)-4 + 5;
	ppem = pem + posn;
	len = ppem[1];
	ppem += pem2bn(TYPE_OCTSTRING, len, ppem, (uint8_t *)ec->private);
	if (memcmp(ppem, ec_oid, sizeof(ec_oid))) return -1;
	ppem += sizeof(ec_oid);
	len = 0x8000 | (ppem[1] - 2) / 2;
	ppem += 4;
	ppem += pem2bn(TYPE_BITSTRING, len, ppem, (uint8_t *)ec->public.x);
	ppem += pem2bn(TYPE_BITSTRING, len, ppem, (uint8_t *)ec->public.y);
	return 0;

}

