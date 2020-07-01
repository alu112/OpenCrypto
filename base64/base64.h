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

#ifndef __BASE64_H__
#define __BASE64_H__

#include <stdint.h>

/* the length inlcudes a string terminator '\0' */
size_t base64_get_encoded_length(const uint8_t *data, size_t ilen);
size_t base64_get_decoded_length(const uint8_t *encoded);
/* don't support inplace encoding */
size_t base64_encode(const uint8_t *data, int ilen, uint8_t *encoded);
/* support inplace decoding */
size_t base64_decode(const uint8_t *encoded, uint8_t *plain);

#endif

