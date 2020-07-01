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

#include <string.h>
#include <stdint.h>
#include "paddings.h"

/* pkcs#5 and pkcs#7 are the same if padding less than 8 bytes */
int pkcs5_pad(uint8_t *buf, int blklen, int len)
{
	int n;
	n = blklen - len % blklen;
	memset(buf+len, n, n);
	return len + n;
}

int pkcs5_unpad(uint8_t *buf, int len)
{
	return buf[len - 1];
}


pad_ctx_t pad_pkcs5 = {
	.pad   = pkcs5_pad,
	.unpad = pkcs5_unpad
};

