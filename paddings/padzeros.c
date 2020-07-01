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

/*
 * this padding algo can't be used in crypto,
 * because it can't find out how many zeros
 * are padded to original binary
 */

int padzeros(uint8_t *buf, int blklen, int len)
{
	int n;
	n = blklen - len % blklen;
	memset(buf+len, 0, n);
	return len + n;
}

int unpadzeros(uint8_t *buf, int len)
{
	int i;
	for (i=0; i<len; i++)
		if (!buf[i]) break;
	return len - i;
}

pad_ctx_t pad_zeros = {
	.pad   = padzeros,
	.unpad = unpadzeros
};

