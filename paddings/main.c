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
#include "paddings.h"

int main_iso7816(int argc, char *argv[])
{
        int i, len;
        uint8_t buf[64] = {"1234567890abcedf9876533"};

        len = strlen(buf);
        printf("origin len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len = pad_iso7816.pad(buf, 8, len);
        printf("pad    len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len -= pad_iso7816.unpad(buf, len);
        printf("unpad  len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        return 0;
}

int main_padzeros(int argc, char *argv[])
{
        int i, len;
        uint8_t buf[64] = {"1234567890abcedf98765333"};

        len = strlen(buf);
        printf("origin len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len = pad_zeros.pad(buf, 8, len);
        printf("pad    len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len -= pad_zeros.unpad(buf, len);
        printf("unpad  len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        return 0;
}

int main_pkcs5(int argc, char *argv[])
{
        int i, len;
        uint8_t buf[64] = {"1234567890abcedf98765333"};

        len = strlen(buf);
        printf("origin len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len = pad_pkcs5.pad(buf, 8, len);
        printf("pad    len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len -= pad_pkcs5.unpad(buf, len);
        printf("unpad  len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        return 0;
}

int main_x9p23(int argc, char *argv[])
{
        int i, len;
        uint8_t buf[64] = {"1234567890abcedf98765333"};

        len = strlen(buf);
        printf("origin len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len = pad_x9p23.pad(buf, 8, len);
        printf("pad    len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        len -= pad_x9p23.unpad(buf, len);
        printf("unpad  len=%2d: ", len);
        for (i=0; i<len; i++)
                printf("%02x ", buf[i]);
        printf("\n");
        return 0;
}

int main(int argc, char *argv[])
{
	int r;
	r = main_iso7816(argc, argv);
	r = main_padzeros(argc, argv);
	r = main_pkcs5(argc, argv);
	r = main_x9p23(argc, argv);
	return r;
}

