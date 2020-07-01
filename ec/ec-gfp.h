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

#ifndef __EC_GFP_H__
#define __EC_GFP_H__

#include "random.h"
#include "gfp.h"


typedef struct ec_keyblob {
    bn_t         private;
    gfp_point_t  public;
    gfp_curve_t  ec;
} ec_keyblob_t;

/* generate private/public key pair from the specific curve */
int  ec_keygen_gfp(char *name, ec_keyblob_t * keys);
/* calculate the secret from my prvkey and peer's public key */
void ecdh_gfp(ec_keyblob_t *mykey, gfp_point_t *peer_pub, gfp_point_t *my_secret);
void ecdsa_sign_gfp(ec_keyblob_t *key, uint8_t *hash, uint32_t hlen, gfp_point_t *signature);
bool ecdsa_verify_gfp(ec_keyblob_t *key, gfp_point_t *peer_pub, uint8_t *hash, uint32_t hlen, gfp_point_t *signature);

/*
 * for faster implementation, check "Appendix G Implementation Aspects" of "NIST SP 800-186 (DRAFT)"
 */

#endif /* __EC_GFP_H__ */

