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
#include <string.h>
#include "sha-common.h"
#include "aes.h"
#include "gmac.h"

/*
 * test vectors coming from 
 * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
 */
int main(int argc, char *argv[])
{
	aes_ctx_t    aes;
	gmac_ctx_t   ctx;
	int     ok;
	uint8_t key[256], iv[256], aad[256], tag[32], newtag[32], pt[512], ct[512], buf[512];

#if 0   /* Count = 0 */
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 0;
        int     AADlen = 0;
        int     Taglen = 128;
        uint8_t Key[] = "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4";
        uint8_t IV[]  = "516c33929df5a3284ff463d7";
        uint8_t PT[]  = "";
        uint8_t AAD[] = "";
        uint8_t CT[]  = "";
        uint8_t Tag[] = "bdc1ac884d332457a1d2664f168c76f0";
#endif
#if 0   /* Count = 0 */
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 0;
        int     AADlen = 0;
        int     Taglen = 64;
        uint8_t Key[] = "8954710576f739df1d238cf81ddaff6efc12499bc368416a8b37888226ae5b02";
        uint8_t IV[]  = "e743cd7dcf42931c42d86e76";
        uint8_t PT[]  = "";
        uint8_t AAD[] = "";
        uint8_t CT[]  = "";
        uint8_t Tag[] = "6a907b21b54f514f";
#endif
#if 0   /* Count = 0 */
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 0;
        int     AADlen = 720;
        int     Taglen = 32;
        uint8_t Key[] = "edb4a4f0540aa3f3cb96e2e35a7e6311a930a9e9a45a7bab21818e3cd8653143";
        uint8_t IV[]  = "5561985a4d765b719f5ac758";
        uint8_t PT[]  = "";
        uint8_t AAD[] = "6eda3acb6381523ba55fc48ae8338a41cac2e4c2fa3033f329f460e0feca4f1c4b8d21d5e2082491a47b0819097602bfe649449a303ae224c34019e342009d2bf79feb6867656c95f3a0df22b3f9bdaa09bb0f6762749512fd7d";
        uint8_t CT[]  = "";
        uint8_t Tag[] = "678d6835";
#endif
#if 0   /* Count = 0 */
	int     Keylen = 256;
	size_t  IVlen  = 96;
	size_t  PTlen  = 128;
	int     AADlen = 128;
	int     Taglen = 128;
	uint8_t Key[] = "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b";
	uint8_t IV[]  = "ac93a1a6145299bde902f21a";
	uint8_t PT[]  = "2d71bcfa914e4ac045b2aa60955fad24";
	uint8_t AAD[] = "1e0889016f67601c8ebea4943bc23ad6";
	uint8_t CT[]  = "8995ae2e6df3dbf96fac7b7137bae67f";
	uint8_t Tag[] = "eca5aa77d51d4a0a14d9c51e1da474ab";
#endif
#if 0   /* Count = 1 */
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 128;
        int     AADlen = 128;
        int     Taglen = 128;
        uint8_t Key[] = "7da3bccaffb3464178ca7c722379836db50ce0bfb47640b9572163865332e486";
        uint8_t IV[]  = "c04fd2e701c3dc62b68738b3";
        uint8_t PT[]  = "fd671cab1ee21f0df6bb610bf94f0e69";
        uint8_t AAD[] = "fec0311013202e4ffdc4204926ae0ddf";
        uint8_t CT[]  = "6be61b17b7f7d494a7cdf270562f37ba";
        uint8_t Tag[] = "5e702a38323fe1160b780d17adad3e96";
#endif
#if 0   /* Count = 2 */
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 128;
        int     AADlen = 128;
        int     Taglen = 128;
        uint8_t Key[] = "a359b9584beec189527f8842dda6b6d4c6a5db2f889635715fa3bcd7967c0a71";
        uint8_t IV[]  = "8616c4cde11b34a944caba32";
        uint8_t PT[]  = "33a46b7539d64c6e1bdb91ba221e3007";
        uint8_t AAD[] = "e1796fca20cb3d3ab0ade69b2a18891e";
        uint8_t CT[]  = "b0d316e95f3f3390ba10d0274965c62b";
        uint8_t Tag[] = "aeaedcf8a012cc32ef25a62790e9334c";
#endif
#if 0   /* Count = 0 */
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 128;
        int     AADlen = 384;
        int     Taglen = 120;
        uint8_t Key[] = "2e6942d537f1a98444c2f9dbdb5d8db42a503a00a17b57d516399569e044a703";
        uint8_t IV[]  = "7eb67721581ed52cfcfc2c4d";
        uint8_t PT[]  = "e5f410fe939e79b7ad33fbd3aaf5856f";
        uint8_t AAD[] = "a96cc73451502c7278b467ac85d5fc14fc1a2f51bc685645b173f0cd9af02d383095de063e6eaa50374ce9bc951e9e61";
        uint8_t CT[]  = "727f5e19a5582e5782bbbe73517f0c04";
        uint8_t Tag[] = "c492319abf12b03b380724ff1483a3";
#endif
#if 0
	int     Keylen = 256;
	size_t  IVlen  = 96;
	size_t  PTlen  = 408;
	int     AADlen = 128;
	int     Taglen = 32;
	uint8_t Key[] = "47bcb66e3101a92459597d4e888b07a9c1a785faedd52366727931319b07214e";
	uint8_t IV[]  = "a224e3f81404e0fd9899bbb8";
	uint8_t PT[]  = "db37b7b5dad31e97800a648031ed4a46b8568fd7c088ac2a473f46e521be5c5a160d2e9c179a80040176ba26e735912a15e196";
	uint8_t AAD[] = "d5a604a4dcda5a9d48c9be1d353b60d8";
	uint8_t CT[]  = "a99419978492e2f2db52e22bda7bab0548c7aff56230526804311d07161eb69b726cc85328b6dcf11338fc5bb0f309e8c0b1e8";
	uint8_t Tag[] = "6d2a8ac8";
#endif
#if 0   /* Count = 0 */
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 408;
        int     AADlen = 384;
        int     Taglen = 120;
        uint8_t Key[] = "055e84fa0cf10ba6abd574933cba1ae4e031ced1b7793d03ab013a0a181aceaf";
        uint8_t IV[]  = "118fac519b8a8fd956f2d616";
        uint8_t PT[]  = "f9e365534773b01b9fcb4ef565153678ddfb3d9db25d29565a25671252fbd7e7c8abc4b4229b201916f4743461f54871c00868";
        uint8_t AAD[] = "bdee4bb1716ee0382607805b9e2a0e19aa2149c5e555471f70d32bf37d714006d8d32ce78d2e33e03dbbc18a65a9fa73";
        uint8_t CT[]  = "5ef702d054012407615a69c5dbe4a17679136175d139eae3f27bb4ff1495a37c99e686803dc49cf54a688048f5e74483a47113";
        uint8_t Tag[] = "48adba35d21a5700650c29ba1d23f5";
#endif
#if 0
        int     Keylen = 256;
        size_t  IVlen  = 8;
        size_t  PTlen  = 128;
        int     AADlen = 128;
        int     Taglen = 112;
        uint8_t Key[] = "ccc5d8418dd4dd459d1d9ecc3927f67391ddf54c5a1c2732438962426a573c5b";
        uint8_t IV[]  = "f8";
        uint8_t PT[]  = "0fece56a5f8890a8faf577a2fd2c2a09";
        uint8_t AAD[] = "c95a2f60d976b2c9537bbcf8049a36f7";
        uint8_t CT[]  = "60fe5d9aed31c71e2bcaf38c2d3bc42f";
        uint8_t Tag[] = "f2911790c1d5eef6dec729cbea01";
#endif

#if 1
        int     Keylen = 256;
        size_t  IVlen  = 1024;
        size_t  PTlen  = 408;
        int     AADlen = 720;
        int     Taglen = 32;
        uint8_t Key[] = "a554516e925009dd856f192213e5376bd072078aeb5d3af971b68cc57f8aa0be";
        uint8_t IV[]  = "26eb2f8c2a9fe5ce6af93be63cf3e670c5f0208933127327ec48693e2ee37e92a0af1c688102fd7b4bb62be1ddd5ba0b8a6ed47137987af768f007857edb2a7465ac0ca7a729846966a46d732445c4524d8ccd18233e25e4ea70cfb31b03d2a564f0948247058e2ac3f963b816315f183efd80c7117e93b4f8592b4901eb6aa5";
        uint8_t PT[]  = "948ac5bf639d55b4d9e46a8846c697e7d1b9456b9c3f77c891d5aca323f18ae78ff8736b8178f91d7fce4041495f616289db79";
        uint8_t AAD[] = "7d2f9b880afbad746bf58c81e31a8e8f88999eb0c6c630ec35db43f1e0952fc7d9bc86154832afd154bc49ffe5e67a1d144b89b7e74a36fdeac8e95b8d9c3b220ef71f38611edc32ac7d9c01a9bb3ec48bc1aaf1dd79921759b6";
        uint8_t CT[]  = "c366146de8b58d3cce004c62a60b24bca3814d3d11ded76bb9f7d47c41191b7e3a7444700bd93fefdf54252cb7cf6041038ca8";
        uint8_t Tag[] = "5016d92a";
#endif

#if 0
        int     Keylen = 256;
        size_t  IVlen  = 96;
        size_t  PTlen  = 128;
        int     AADlen = 128;
        int     Taglen = 128;
        uint8_t Key[] = "";
        uint8_t IV[]  = "";
        uint8_t PT[]  = "";
        uint8_t AAD[] = "";
        uint8_t CT[]  = "";
        uint8_t Tag[] = "";
#endif

	hex2ba(Key, key, sizeof(key));
	hex2ba(IV,  iv,  sizeof(iv));
	hex2ba(PT,  pt,  sizeof(pt));
	hex2ba(AAD, aad, sizeof(aad));
	hex2ba(CT,  ct,  sizeof(ct));
	hex2ba(Tag, tag, sizeof(tag));

	memcpy(buf, pt, PTlen/8);
	aes_init(&aes, key, Keylen);
	
	gmac_init(&ctx, iv, IVlen/8, aad, AADlen/8, Taglen/8, (blk_ctx_t *)&aes);
	ctx.encrypt(&ctx, buf, PTlen/8, newtag);
	if (memcmp(ct, buf, PTlen/8))
		printf("encrypt failed\n");
	else
		printf("encrypt succeeded\n");
	if (memcmp(tag, newtag, Taglen/8))
		printf("tag verify failed\n");
	else
		printf("tag verify succeeded\n");

	gmac_init(&ctx, iv, IVlen/8, aad, AADlen/8, Taglen/8, (blk_ctx_t *)&aes);
	ok = ctx.decrypt(&ctx, buf, PTlen/8, tag);
	
	if (memcmp(pt, buf, PTlen/8))
		printf("decrypt failed\n");
	else
		printf("decrypt succeeded\n");
	if (ok != 0)
		printf("tag verify failed\n");
	else
		printf("tag verify succeeded\n");

	return 0;
}

