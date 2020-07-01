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

#ifndef __RANDOM_H__
#define __RANDOM_H__

#include <stdint.h>
#include "bn.h"

/* if array u8[] is longer than nbits, the caller has to clear it first */
int  get_random(int nbits, uint8_t u8[]);

/* bn will be cleared first inside bn_gen_random() */
uint32_t bn_gen_random(int bitlength, bn_t bn);

#endif /* __RANDOM_H__ */

