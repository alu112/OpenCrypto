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

int x9p23_pad(uint8_t *buf, int blklen, int len)
{
	int n;
	n = blklen - len % blklen;
	memset(buf+len, 0, n-1);
	buf[len+n-1] = n;
	return len + n;
}

int x9p23_unpad(uint8_t *buf, int len)
{
	return buf[len - 1];
}

pad_ctx_t pad_x9p23 = {
	.pad   = x9p23_pad,
	.unpad = x9p23_unpad
};

