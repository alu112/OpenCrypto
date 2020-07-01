#
#   Copyright 2020 Andrew Li, Gavin Li
#
#   li.andrew.mail@gmail.com
#   gavinux@gmail.com
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

TOP = .
INCLUDE = -I$(TOP)/bignumber -I$(TOP)/prime \
	  -I$(TOP)/paddings -I$(TOP)/des -I$(TOP)/aes -I$(TOP)/mode \
	  -I$(TOP)/random -I$(TOP)/rsa -I$(TOP)/dh -I$(TOP)/base64 \
	  -I$(TOP)/gf -I$(TOP)/hash -I$(TOP)/hmac -I$(TOP)/gmac
CFLAGS += -O0 -g3 -Wunused -fPIC
#CFLAGS += -O2 -g0 -Wunused -fPIC
CFLAGS += $(INCLUDE)
CFLAGS += $(CPPFLAGS)
CC = gcc

SRCS := stream/lfsr4.c stream/lfsr5.c stream/lfsr8.c stream/lfsr16.c stream/lfsr32.c \
	des/des.c \
	aes/aes.c \
	base64/base64.c \
	bignumber/bn-gfp.c bignumber/bn-gf2m.c \
	dh/elgamal.c  \
	dsa/dsa-param.c dsa/dsa.c \
	ec/ec-param-gfp.c ec/ec-param-gf2m.c ec/ec-param.c ec/ec-gfp.c ec/ec-gf2m.c ec/ec-pem.c \
	gf/gfp.c gf/gf2m.c \
	gmac/gmac.c \
	hash/sha-common.c hash/sha1.c hash/sha256.c hash/sha512.c hash/sha3.c \
	hmac/hmac.c \
	mode/cbc.c mode/ctr.c mode/ecb.c mode/cfb.c mode/ofb.c \
	paddings/iso7816.c paddings/padzeros.c paddings/pkcs5.c paddings/x9p23.c \
	prime/primality.c \
	random/random.c \
	rsa/rsa.c rsa/rsa-pem.c \
	rsa/rsaes-oaep.c rsa/rsaes-pkcs1.c rsa/rsassa-pss.c rsa/rsassa-pkcs1.c

OBJS := $(SRCS:.c=.o)
LIBS := libs/libcrypto.so libs/crypto.a

APPSRCS := stream/main.c \
	des/main.c \
	aes/main.c \
	base64/main.c \
	bignumber/main.c bignumber/main-mont.c bignumber/main-mont1.c \
	dsa/main.c \
	ec/main-gfp.c ec/main-gf2m.c ec/main-keygen-nist.c ec/main-nist.c \
	gmac/main.c gmac/main-nist.c \
	hash/main1.c \
	hash/main256.c hash/main224.c hash/main512.c hash/main384.c \
	hash/main3-224.c hash/main3-256.c hash/main3-384.c hash/main3-512.c \
	hash/main-shake.c \
	hash/main-nist.c \
	hmac/main1.c hmac/main256.c hmac/main224.c hmac/main512.c hmac/main384.c \
	hmac/main3-224.c hmac/main3-256.c hmac/main3-384.c hmac/main3-512.c \
	hmac/main-nist.c \
	mode/main.c mode/main-nist-aes.c mode/main-nist-3des.c \
	mode/main-nist-aes-mct.c \
	paddings/main.c \
	prime/main.c \
	random/main.c \
	rsa/main.c rsa/main-oaep.c rsa/main-pkcs1.c rsa/main-nist-dp.c rsa/main-nist-sp.c \
	rsa/main-nist-pss.c rsa/main-nist-pkcs1.c \
	example/main-encrypt.c
#APPS := $(subst /,-,$(APPSRCS:.c=))
APPS := $(APPSRCS:.c=)

DIRS := libs bin

.PHONY: dirs all clean

all: dirs $(APPS)

dirs:
	mkdir -p $(DIRS)
	cp rsa/rsa-main.sh bin/
	cp ec/ec-main-gfp.sh bin/

%.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS)

libs/libcrypto.so: $(OBJS)
	$(CC) -shared -o $@ $^
	#$(CC) -shared -o $@ $^ -T hash.ld

bin/crypto.a: $(OBJS)
	ar rcs $@ $^

%:%.c libs/libcrypto.so
	$(CC) $^ -o bin/$(subst /,-,$@) $(CFLAGS) -Llibs -lcrypto

%:%.c libs/crypto.a
	$(CC) $^ -o bin/$(subst /,-,$@) $(CFLAGS)

bin/rsa-gmp: rsa/rsa-gmp.c bin/crypto.a
	$(CC) $^ -o $@ $(CFLAGS) -lgmp

clean:
	rm -fr $(DIRS) $(OBJS) *.pem

