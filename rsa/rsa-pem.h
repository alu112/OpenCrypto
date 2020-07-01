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

#ifndef __RSA_PEM_H__
#define __RSA_PEM_H__

#include <stdint.h>


#define TYPE_INTEGER   0x02
#define TYPE_BITSTRING 0x03
#define TYPE_SEQUENCE  0x30
int rsa_prvkey2pem(rsa_key_t * rsa, char *pemfilename);
int rsa_pem2prvkey(char *pemfilename, rsa_key_t *rsa);
int rsa_pubkey2pem(rsa_key_t *rsa, char* pemfilename);
int rsa_pem2pubkey(char *pemfilename, rsa_key_t *rsa);

#endif /* __RSA_PEM_H__ */

