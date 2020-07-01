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

#ifndef __PADDINGS_H__
#define __PADDINGS_H__

#include <stdint.h>

typedef struct pad_ctx pad_ctx_t;

struct pad_ctx {
        int   (*pad)(uint8_t *buf, int blklen, int len);
        int (*unpad)(uint8_t *buf, int len);
};

extern pad_ctx_t pad_iso7816, pad_zeros, pad_pkcs5, pad_x9p23; 

/* pkcs#5 and pkcs#7 are the same if padding less than 8 bytes */
/* pad_zeros can't correctly identify last byte when unpadding if last byte is zero */

#endif /* __PADDINGS_H__ */

