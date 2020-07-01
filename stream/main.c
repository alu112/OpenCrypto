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
#include <stdint.h>
#include "lfsr.h"

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	uint32_t r0;
	uint32_t r1;

	r0 = lfsr5();
	while(1) {
		r1 = lfsr5();
		printf("%8x ", r1);
		if (r0 == r1) break;
	}
	return 0;
}
