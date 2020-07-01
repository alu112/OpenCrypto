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

#ifndef __LFSR_H__
#define __LFSR_H__

#include <stdint.h>

uint32_t lfsr4(void);
uint32_t lfsr5(void);
uint32_t lfsr8(void);
uint32_t lfsr16(void);
uint32_t lfsr32(void);

#endif /* __LFSR_H__ */

