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
#include <string.h>
#include "rsa.h"
#include "rsaes-oaep.h"

/*
 * test vector is from RSA-oaep_spec.pdf
 * the rsaes-oaep.c needs to be compiled as: 
 *     make clean
 *     make CPPFLAGS="-DPKCS1_OAEP_TESTVECT -DMAXBITLEN=1024"
 */
int main(int argc, char *argv[])
{
	const int keybits = 1024;
	const int nbytes = keybits / 8;
	int nbits;
	int rs, msglen;
	rsa_key_t pub, prv;
	rsaes_oaep_ctx_t ctx;
	uint8_t msg_in[] = {"\xd4\x36\xe9\x95\x69\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49"};
	uint8_t encoded_msg[nbytes], decoded_msg[nbytes], out[nbytes];
	uint32_t e=0x11;
	uint8_t p[] = {"eecfae81b1b9b3c908810b10a1b5600199eb9f44aef4fda493b81a9e3d84f632124ef0236e5d1e3b7e28fae7aa040a2d5b252176459d1f397541ba2a58fb6599"};
	uint8_t q[] = {"c97fb1f027f453f6341233eaaad1d9353f6c42d08866b1d05a0f2035028b9d869840b41666b42e92ea0da3b43204b5cfce3352524d0416a5a441e700af461503"};
	uint8_t em[] = {
		"\x00\xeb\x7a\x19\xac\xe9\xe3\x00"
		"\x63\x50\xe3\x29\x50\x4b\x45\xe2"
		"\xca\x82\x31\x0b\x26\xdc\xd8\x7d"
		"\x5c\x68\xf1\xee\xa8\xf5\x52\x67"
		"\xc3\x1b\x2e\x8b\xb4\x25\x1f\x84"
		"\xd7\xe0\xb2\xc0\x46\x26\xf5\xaf"
		"\xf9\x3e\xdc\xfb\x25\xc9\xc2\xb3"
		"\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb"
		"\x4c\xdc\xfe\x4f\xf4\x77\x28\xb4"
		"\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a"
		"\xb4\x8d\x28\x69\xd5\x02\x41\x21"
		"\x43\x58\x11\x59\x1b\xe3\x92\xf9"
		"\x82\xfb\x3e\x87\xd0\x95\xae\xb4"
		"\x04\x48\xdb\x97\x2f\x3a\xc1\x4f"
		"\x7b\xc2\x75\x19\x52\x81\xce\x32"
		"\xd2\xf1\xb7\x6d\x4d\x35\x3e\x2d"
	};
	uint8_t cipher[] = {
		"\x12\x53\xe0\x4d\xc0\xa5\x39\x7b"
		"\xb4\x4a\x7a\xb8\x7e\x9b\xf2\xa0"
		"\x39\xa3\x3d\x1e\x99\x6f\xc8\x2a"
		"\x94\xcc\xd3\x00\x74\xc9\x5d\xf7"
		"\x63\x72\x20\x17\x06\x9e\x52\x68"
		"\xda\x5d\x1c\x0b\x4f\x87\x2c\xf6"
		"\x53\xc1\x1d\xf8\x23\x14\xa6\x79"
		"\x68\xdf\xea\xe2\x8d\xef\x04\xbb"
		"\x6d\x84\xb1\xc3\x1d\x65\x4a\x19"
		"\x70\xe5\x78\x3b\xd6\xeb\x96\xa0"
		"\x24\xc2\xca\x2f\x4a\x90\xfe\x9f"
		"\x2e\xf5\xc9\xc1\x40\xe5\xbb\x48"
		"\xda\x95\x36\xad\x87\x00\xc8\x4f"
		"\xc9\x13\x0a\xde\xa7\x4e\x55\x8d"
		"\x51\xa7\x4d\xdf\x85\xd8\xb5\x0d"
		"\xe9\x68\x38\xd6\x06\x3e\x09\x55"
	};

	memset(&prv, 0, sizeof(prv));
	memset(&pub, 0, sizeof(pub));
	bn_hex2bn(p, prv.p);
	bn_hex2bn(q, prv.q);
	bn_qw2bn(e, prv.e);
	rsa_keygen(keybits, NULL, &prv, &pub);
	nbits = bn_getmsbposn(prv.n);
	rs = rsaes_oaep_init(&ctx, nbits, eHASH_SHA1);
	rs = ctx.encodepad(&ctx, strlen(msg_in), msg_in, NULL, encoded_msg);
	if (memcmp(em, encoded_msg, nbytes)) {
		printf("RSA-OAEP encoding PAD FAILED\n");
		rs = -1;
	}
	rsa_encrypt(&pub, encoded_msg, nbytes, out);
	if (memcmp(cipher, out, nbytes)) {
		printf("RSA-OAEP encrypt FAILED\n");
		rs = -1;
	}
	rsa_decrypt(&prv, cipher, nbytes, encoded_msg);
	if (memcmp(em, encoded_msg, nbytes)) {
		printf("RSA-OAEP decrypt FAILED\n");
		rs = -1;
	}
	rs |= ctx.decodepad(&ctx, nbytes, em, NULL, &msglen, decoded_msg);
	if (msglen != strlen(msg_in)) {
		printf("RSA-OAEP decoding PAD msglen FAILED\n");
		rs = -1;
	}
	if (memcmp(decoded_msg, msg_in, msglen)) {
		printf("RSA-OAEP decode PAD msg FAILED\n");
		rs = -1;
	}
	if (rs) {
		printf("Did you compile with this command line for this test?\n");
		printf("\tmake clean; make CPPFLAGS=\"-DPKCS1_OAEP_TESTVECT -DMAXBITLEN=1024\"\n");
	}
	else
		printf("RSAES-OAEP TEST SUCCEEDED\n");

	return rs;
}

