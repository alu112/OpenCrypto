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

/*
 * openssl put 00 before a number if MSbit is 1 to make it positive
 * BUT, don't put 00 before it in bn_hex2bn() is the string length
 * is longer then PRIVATE_LEN, otherwise will get wrong result
 * 
 * openssl ecparam -list_curves
 * openssl ecparam -name secp256k1 -param_enc explicit -out secp256k1.pem
 * openssl ecparam -in secp256k1.pem -noout -text
 */

#include <string.h>
#include "ec-param.h"

/* Prime Field Curves */
int ec_secp192k1(gfp_curve_t * ec);
int ec_secp192r1(gfp_curve_t * ec);
int ec_prime192v1(gfp_curve_t * ec);
int ec_secp224k1(gfp_curve_t * ec);
int ec_secp224r1(gfp_curve_t * ec);
int ec_secp256k1(gfp_curve_t * ec);
int ec_prime256v1(gfp_curve_t * ec);
int ec_secp384r1(gfp_curve_t * ec);
int ec_secp521r1(gfp_curve_t * ec);

int ec_brainpoolP512r1(gfp_curve_t * ec);


int ec_secp192k1(gfp_curve_t * ec)
{
	/* secp192k1 curve    http://www.secg.org/sec2-v2.pdf */
	bn_hex2bn("0xfffffffffffffffffffffffffffffffffffffffeffffee37", ec->prime);
	bn_hex2bn("0x0", ec->a);
	bn_hex2bn("0x3", ec->b);
	bn_hex2bn("0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d", ec->g.x);
	bn_hex2bn("0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d", ec->g.y);
	bn_hex2bn("0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	ec->keylen = 192;
	return ec->keylen;
}

int ec_secp192r1(gfp_curve_t * ec)
{
	/* secp192r1 curve    http://www.secg.org/sec2-v2.pdf */
	bn_hex2bn("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", ec->prime);
	bn_hex2bn("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", ec->a);
	bn_hex2bn("0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", ec->b);
	bn_hex2bn("0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", ec->g.x);
	bn_hex2bn("0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", ec->g.y);
	bn_hex2bn("0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	ec->keylen = 192;
	return ec->keylen;
}

int ec_prime192v1(gfp_curve_t * ec)
{
	bn_hex2bn("0xfffffffffffffffffffffffffffffffeffffffffffffffff", ec->prime);
	bn_hex2bn("0xfffffffffffffffffffffffffffffffefffffffffffffffc", ec->a);
	bn_hex2bn("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", ec->b);
	bn_hex2bn("0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", ec->g.x);
	bn_hex2bn("0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811", ec->g.y);
	bn_hex2bn("0xffffffffffffffffffffffff99def836146bc9b1b4d22831", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	bn_hex2bn("0x3045ae6fc8422f64ed579528d38120eae12196d5", ec->seed);
	ec->keylen = 192;
	return ec->keylen;
}

int ec_secp224k1(gfp_curve_t * ec)
{
	bn_hex2bn("0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d", ec->prime);
	bn_hex2bn("0x0", ec->a);
	bn_hex2bn("0x5", ec->b);
	bn_hex2bn("0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c", ec->g.x);
	bn_hex2bn("0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5", ec->g.y);
	bn_hex2bn("0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	ec->keylen = 224;
	return ec->keylen;
}

int ec_secp224r1(gfp_curve_t * ec)
{
	bn_hex2bn("0xffffffffffffffffffffffffffffffff000000000000000000000001", ec->prime);
	bn_hex2bn("0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe", ec->a);
	bn_hex2bn("0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", ec->b);
	bn_hex2bn("0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", ec->g.x);
	bn_hex2bn("0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", ec->g.y);
	bn_hex2bn("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	bn_hex2bn("0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5", ec->seed);
	ec->keylen = 224;
	return ec->keylen;
}

int ec_secp256k1(gfp_curve_t * ec)
{
	/* secp256k1 curve:
	 * openssl ecparam -name secp256k1 -param_enc explicit -out secp256k1.pem
	 * openssl ecparam -in secp256k1.pem -noout -text
	 */
	bn_hex2bn("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", ec->prime);
	bn_hex2bn("0x0", ec->a);
	bn_hex2bn("0x7", ec->b);
	bn_hex2bn("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", ec->g.x);
	bn_hex2bn("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", ec->g.y);
	bn_hex2bn("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	ec->keylen = 256;
	return ec->keylen;
}

int ec_prime256v1(gfp_curve_t * ec)
{
	/* prime256v1 curve:
	 * openssl ecparam -name prime256v1 -param_enc explicit -out prime256v1.pem
	 * openssl ecparam -in prime256v1.pem -noout -text
	 */
	bn_hex2bn("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff", ec->prime);
	bn_hex2bn("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc", ec->a);
	bn_hex2bn("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", ec->b);
	bn_hex2bn("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", ec->g.x);
	bn_hex2bn("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", ec->g.y);
	bn_hex2bn("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	bn_hex2bn("0xc49d360886e704936a6678e1139d26b7819f7e90", ec->seed);
	ec->keylen = 256;
	return ec->keylen;
}

int ec_secp384r1(gfp_curve_t * ec)
{
	bn_hex2bn("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", ec->prime);
	bn_hex2bn("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", ec->a);
	bn_hex2bn("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", ec->b);
	bn_hex2bn("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", ec->g.x);
	bn_hex2bn("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", ec->g.y);
	bn_hex2bn("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	bn_hex2bn("0xa335926aa319a27a1d00896a6773a4827acdac73", ec->seed);
	ec->keylen = 384;
	return ec->keylen;
}

int ec_secp521r1(gfp_curve_t * ec)
{
	bn_hex2bn("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", ec->prime);
	bn_hex2bn("0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", ec->a);
	bn_hex2bn("0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", ec->b);
	bn_hex2bn("0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", ec->g.x);
	bn_hex2bn("0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", ec->g.y);
	bn_hex2bn("0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	bn_hex2bn("0xd09e8800291cb85396cc6717393284aaa0da64ba", ec->seed);
	ec->keylen = 521;
	return ec->keylen;
}


int ec_brainpoolP512r1(gfp_curve_t * ec)
{
	/* brainpoolP512r1 curve:
	 * openssl ecparam -name brainpoolP512r1 -param_enc explicit -out brainpoolP512r1.pem
	 * openssl ecparam -in brainpoolP512r1.pem -noout -text
	 */
	bn_hex2bn("0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", ec->prime);
	bn_hex2bn("0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca", ec->a);
	bn_hex2bn("0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723", ec->b);
	bn_hex2bn("0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822", ec->g.x);
	bn_hex2bn("0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892", ec->g.y);
	bn_hex2bn("0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069", ec->order);
	bn_hex2bn("0x1", ec->cofactor);
	ec->keylen = 512;
	return ec->keylen;
}

