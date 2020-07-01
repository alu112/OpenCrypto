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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "base64.h"

int main(int argc, char *argv[])
{
	//build_decoding_table();

	int   working = 0;
	size_t len;
	
	uint8_t txt1[] = {"Hello World!\nHi\n"};
	uint8_t enc1[32];
	uint8_t txt2[32];

	if (argc != 4) {
		printf("Usage:\n");
		printf("    %s [ -d | -e ] infile outfile\n", argv[0]);
		printf("        -d decode\n");
		printf("        -e encode\n");
		exit(-1);
	}
	len = base64_get_encoded_length(txt1, sizeof(txt1));
	len = base64_encode(txt1, sizeof(txt1), enc1);
	printf("encoded length=%ld, output: %s\n", len, enc1);

	len = base64_get_decoded_length(enc1);
	len = base64_decode(enc1, txt2);
	printf("decoded length=%ld, outpus: %s\n", len, txt2);
	
	uint8_t enc2[] = {"IQ=="};
	uint8_t dat2[4] = { '!', };

	len = base64_encode(dat2, 1, enc2);
	printf("encoded length=%ld, output: %s\n", len, enc2);
	len = base64_get_decoded_length(enc2);
	printf("decoded length=%ld\n", len);
	len = base64_decode(enc2, dat2);
	printf("decoded length=%ld, output: %c\n", len, dat2[0]);


	FILE *fpi, *fpo;
	int i;
	uint8_t buf[2048], enc[2048], dec[2048];
	uint8_t pem_hdr[] = {"-----BEGIN RSA PRIVATE KEY-----\n"};
	uint8_t pem_ftr[] = {"-----END RSA PRIVATE KEY-----\n"};

	fpi = fopen(argv[2], "r");
	fpo = fopen(argv[3], "wb+");
	if (!strcmp(argv[1], "-e")) {
		len = fread(buf, 1, 2048, fpi);
		fclose(fpi);
		len = base64_encode(buf, len, enc);
	        fwrite(pem_hdr, strlen(pem_hdr), 1, fpo);
	        for (i=0; i<(len/64)*64; i+=64) {
        	        fwrite(&enc[i], 64, 1, fpo);
                	fwrite("\n", 1, 1, fpo);
	        }
        	fputs(&enc[i], fpo); fwrite("\n", 1, 1, fpo);
	        fwrite(pem_ftr, strlen(pem_ftr), 1, fpo);
        	fclose(fpo);
	}
	else {
		while(fgets(buf, 76, fpi)) {
			if (!strncmp(buf, "-----", 5)) { working = !working; continue; }
			if (!working) continue;
			buf[strlen(buf)-1] = '\0'; /* remove \n */
			len = base64_decode(buf, dec);
			fwrite(dec, len, 1, fpo);
			for (i=0; i<len; i++)
				printf("%02x ", dec[i]);
			printf("\n");
		}
		fclose(fpo);
		fclose(fpi);
	}
	return 0;
}

