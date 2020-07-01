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

int iso7816_pad(uint8_t *buf, int blklen, int len)
{
	int n;
	n = blklen - len % blklen;
	buf[len] = 0x80;
	memset(buf+len+1, 0, n-1);
	return len + n;
}

/* return how many bytes been removed */
int iso7816_unpad(uint8_t *buf, int len)
{
	int i;
	for (i=0; i<len; i++)
		if (buf[len - i - 1] == 0x80) break;

	return i+1;
}

pad_ctx_t pad_iso7816 = {
	.pad   = iso7816_pad,
	.unpad = iso7816_unpad
};

