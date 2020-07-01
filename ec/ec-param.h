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

#ifndef __EC_CURVES_H__
#define __EC_CURVES_H__

#include "gfp.h"

int ec_getcurve(char *name, gfp_curve_t *ec);

/* Prime Field Curves */
int ec_secp192k1(gfp_curve_t *ec);
int ec_secp192r1(gfp_curve_t *ec);
int ec_prime192v1(gfp_curve_t *ec);
int ec_secp224k1(gfp_curve_t *ec);
int ec_secp224r1(gfp_curve_t *ec);
int ec_secp256k1(gfp_curve_t *ec);
int ec_prime256v1(gfp_curve_t *ec);
int ec_secp384r1(gfp_curve_t *ec);
int ec_secp521r1(gfp_curve_t *ec);

/* K Curves: Koblitz Curves */
int ec_sect163k1(gfp_curve_t *ec);
int ec_sect233k1(gfp_curve_t *ec);
int ec_sect283k1(gfp_curve_t *ec);
int ec_sect409k1(gfp_curve_t *ec);
int ec_sect571k1(gfp_curve_t *ec);

/* B Curves: Pseudorandom Curves */
int ec_sect163r2(gfp_curve_t *ec);
int ec_sect233r1(gfp_curve_t *ec);
int ec_sect283r1(gfp_curve_t *ec);
int ec_sect409r1(gfp_curve_t *ec);
int ec_sect571r1(gfp_curve_t *ec);


int ec_brainpoolP512r1(gfp_curve_t *ec);


#endif /* __EC_CURVES_H__ */

