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

/* K-Curves: Koblitz Curves */
int ec_sect163k1(gfp_curve_t *ec);
int ec_sect233k1(gfp_curve_t *ec);
int ec_sect283k1(gfp_curve_t *ec);
int ec_sect409k1(gfp_curve_t *ec);
int ec_sect571k1(gfp_curve_t *ec);

/* B-Curves: Pseudorandom Curves */
int ec_sect163r2(gfp_curve_t *ec);
int ec_sect233r1(gfp_curve_t *ec);
int ec_sect283r1(gfp_curve_t *ec);
int ec_sect409r1(gfp_curve_t *ec);
int ec_sect571r1(gfp_curve_t *ec);

int ec_sect163k1(gfp_curve_t *ec)
{
	bn_hex2bn("0x800000000000000000000000000000000000000c9", ec->prime);
	bn_hex2bn("1", ec->a);
	bn_hex2bn("1", ec->b);
	bn_hex2bn("0x2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8", ec->g.x);
	bn_hex2bn("0x289070fb05d38ff58321f2e800536d538ccdaa3d9", ec->g.y);
	bn_hex2bn("0x4000000000000000000020108a2e0cc0d99f8a5ef", ec->order);
	bn_hex2bn("2", ec->cofactor);
	ec->keylen = 163;
	return ec->keylen;
}

int ec_sect163r2(gfp_curve_t *ec)
{
	bn_hex2bn("0x800000000000000000000000000000000000000c9", ec->prime);
	bn_hex2bn("1", ec->a);
	bn_hex2bn("0x20a601907b8c953ca1481eb10512f78744a3205fd", ec->b);
	bn_hex2bn("0x3f0eba16286a2d57ea0991168d4994637e8343e36", ec->g.x);
	bn_hex2bn("0x0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1", ec->g.y);
	bn_hex2bn("0x40000000000000000000292fe77e70c12a4234c33", ec->order);
	bn_hex2bn("0x2", ec->cofactor);
	ec->keylen = 163;
	return ec->keylen;
}

int ec_sect233k1(gfp_curve_t *ec)
{
	bn_hex2bn("0x20000000000000000000000000000000000000004000000000000000001", ec->prime);
	bn_hex2bn("0x0", ec->a);
	bn_hex2bn("0x1", ec->b);
	bn_hex2bn("0x17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126", ec->g.x);
	bn_hex2bn("0x1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3", ec->g.y);
	bn_hex2bn("0x08000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf", ec->order);
	bn_hex2bn("0x4", ec->cofactor);
	ec->keylen = 233;
	return ec->keylen;
}

int ec_sect233r1(gfp_curve_t *ec)
{
	bn_hex2bn("0x020000000000000000000000000000000000000004000000000000000001", ec->prime);
	bn_hex2bn("0x1", ec->a);
	bn_hex2bn("0x66647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad", ec->b);
	bn_hex2bn("0x00fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b", ec->g.x);
	bn_hex2bn("0x01006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052", ec->g.y);
	bn_hex2bn("0x01000000000000000000000000000013e974e72f8a6922031d2603cfe0d7", ec->order);
	bn_hex2bn("0x2", ec->cofactor);
	bn_hex2bn("0x74d59ff07f6b413d0ea14b344b20a2db049b50c3", ec->seed);
	ec->keylen = 233;
	return ec->keylen;
}

int ec_sect283k1(gfp_curve_t *ec)
{
	bn_hex2bn("0x0800000000000000000000000000000000000000000000000000000000000000000010a1", ec->prime);
	bn_hex2bn("0x0", ec->a);
	bn_hex2bn("0x1", ec->b);
	// Polynomial basis:
	bn_hex2bn("0x0503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836", ec->g.x);
	bn_hex2bn("0x01ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259", ec->g.y);
	// Normal basis:
	//bn_hex2bn("0x3ab9593f8db09fc188f1d7c4ac9fcc3e57fcd3bdb15024b212c70229de5fcd92eb0ea60", ec->g.x);
	//bn_hex2bn("0x2118c4755e7345cd8f603ef93b98b106fe8854ffeb9a3b304634cc83a0e759f0c2686b1", ec->g.y);
	bn_hex2bn("0x01ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61", ec->order);
	bn_hex2bn("0x04", ec->cofactor);
	ec->keylen = 283;
	return ec->keylen;
}

int ec_sect283r1(gfp_curve_t *ec)
{
	bn_hex2bn("0x800000000000000000000000000000000000000000000000000000000000000000010a1", ec->prime);
	bn_hex2bn("0x1", ec->a);
	bn_hex2bn("0x27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5", ec->b);
	bn_hex2bn("0x5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053", ec->g.x);
	bn_hex2bn("0x3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4", ec->g.y);
	bn_hex2bn("0x3ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307", ec->order);
	bn_hex2bn("0x02", ec->cofactor);
	bn_hex2bn("0x77e2b07370eb0f832a6dd5b62dfc88cd06bb84be", ec->seed);
	ec->keylen = 283;
	return ec->keylen;
}

int ec_sect409k1(gfp_curve_t *ec)
{
        bn_hex2bn("0x02000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001", ec->prime);
        bn_hex2bn("0x0", ec->a);
        bn_hex2bn("0x1", ec->b);
        bn_hex2bn("0x0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746", ec->g.x);
        bn_hex2bn("0x01e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b", ec->g.y);
        bn_hex2bn("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf", ec->order);
	bn_hex2bn("0x4", ec->cofactor);
        ec->keylen = 409;
        return ec->keylen;
}

int ec_sect409r1(gfp_curve_t *ec)
{
        bn_hex2bn("0x02000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000001", ec->prime);
        bn_hex2bn("0x1", ec->a);
        bn_hex2bn("0x21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", ec->b);
        bn_hex2bn("0x015d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", ec->g.x);
        bn_hex2bn("0x0061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", ec->g.y);
        bn_hex2bn("0x010000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173", ec->order);
        bn_hex2bn("0x2", ec->cofactor);
        bn_hex2bn("0x4099b5a457f9d69f79213d094c4bcd4d4262210b", ec->seed);
        ec->keylen = 409;
        return ec->keylen;
}

int ec_sect571k1(gfp_curve_t *ec)
{
	bn_hex2bn("0x080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000425", ec->prime);
	bn_hex2bn("0x00", ec->a);
	bn_hex2bn("0x01", ec->b);
	bn_hex2bn("0x026eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972", ec->g.x);
	bn_hex2bn("0x0349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3", ec->g.y);
	bn_hex2bn("0x020000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001", ec->order);
	bn_hex2bn("0x4", ec->cofactor);
	ec->keylen = 571;
	return ec->keylen;
}

int ec_sect571r1(gfp_curve_t *ec)
{
	bn_hex2bn("0x80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000425", ec->prime);
	bn_hex2bn("0x01", ec->a);
	bn_hex2bn("0x2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a", ec->b);
	bn_hex2bn("0x303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19", ec->g.x);
	bn_hex2bn("0x37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b", ec->g.y);
	bn_hex2bn("0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47", ec->order);
	bn_hex2bn("0x2", ec->cofactor);
	bn_hex2bn("0x2aa058f73a0e33ab486b0f610410c53a7f132310", ec->seed);
	ec->keylen = 571;
	return ec->keylen;
}

