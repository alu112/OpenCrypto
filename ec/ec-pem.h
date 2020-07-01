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

#ifndef __EC_PEM_H__
#define __EC_PEM_H__

#include <stdint.h>
#include "ec-gfp.h"


#define TYPE_INTEGER   0x02
#define TYPE_BITSTRING 0x03
#define TYPE_OCTSTRING 0x04
#define TYPE_SEQUENCE  0x30
int ec_prvkey2pem(ec_keyblob_t * ec, char *pemfilename);
int ec_pem2prvkey(char *pemfilename, ec_keyblob_t *ec);
int ec_pubkey2pem(ec_keyblob_t *ec, char* pemfilename);
int ec_pem2pubkey(char *pemfilename, ec_keyblob_t *ec);

#endif /* __EC_PEM_H__ */

