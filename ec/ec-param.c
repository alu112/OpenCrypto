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
#include "ec-param.h"

int ec_getcurve(char *name, gfp_curve_t *ec)
{
	/* P-Curves */
	if (!strcmp(name, "secp192k1"))  return ec_secp192k1(ec);
	if (!strcmp(name, "secp192r1"))  return ec_secp192r1(ec);
	if (!strcmp(name, "prime192v1")) return ec_prime192v1(ec);
	if (!strcmp(name, "secp224k1"))  return ec_secp224k1(ec);
	if (!strcmp(name, "secp224r1"))  return ec_secp224r1(ec);
	if (!strcmp(name, "secp256k1"))  return ec_secp256k1(ec);
	if (!strcmp(name, "prime256v1")) return ec_prime256v1(ec);
	if (!strcmp(name, "secp384r1"))  return ec_secp384r1(ec);
	if (!strcmp(name, "secp521r1"))  return ec_secp521r1(ec);

	/* K-Curves */
	if (!strcmp(name, "sect163k1"))  return ec_sect163k1(ec);
	if (!strcmp(name, "sect233k1"))  return ec_sect233k1(ec);
	if (!strcmp(name, "sect283k1"))  return ec_sect283k1(ec);
	if (!strcmp(name, "sect409k1"))  return ec_sect409k1(ec);
	if (!strcmp(name, "sect571k1"))  return ec_sect571k1(ec);

	/* B-Curves */
	if (!strcmp(name, "sect163r2"))  return ec_sect163r2(ec);
	if (!strcmp(name, "sect233r1"))  return ec_sect233r1(ec);
	if (!strcmp(name, "sect283r1"))  return ec_sect283r1(ec);
	if (!strcmp(name, "sect409r1"))  return ec_sect409r1(ec);
	if (!strcmp(name, "sect571r1"))  return ec_sect571r1(ec);

	/* BrainPool */
	if (!strcmp(name, "brainpoolP512r1"))  return ec_brainpoolP512r1(ec);
	return -1;
}

