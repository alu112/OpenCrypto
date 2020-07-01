# OpenCrypto project
A cryptographic algorithms implementation project
There are lots of test cases have been written.

Apache 2.0 License

Authors:
- Andrew Li li.andrew.mail@gmail.com
- Gavin Li gavinux@gmail.com
### Algorithms:
- AES, DES, TripleDES, 
- DSA
- RSA: RSAES-OAEP, RSAES-PKCS1-v1.5, RSASSA-PSS, RSASSA-PKCS1-v1.5
- Elliptic Curve(GFP and GF2^m)
- Elgamal
- SHA1, 
- SHA2: SHA224, SHA256, SHA384, SHA512, SHA512-224, SHA512-256
- SHA3: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256
- HMAC, GMAC
- Modes: ECB, CBC, CTR, CFB, OFB
- Paddings: iso7816, padzeros, pkcs5, x9p23
- Base64 encoding/decoding
- Prime number: Miller-Rabin Primality Test
- Random Generator: HAC Algorithm 5.15
- Bignumber Library: GFP and GF2^m


### Initial project checkin
#### Test Environment: Ubuntu-18.0.4
#### Know issue:
    - Prime number generator is way too slow.
    - Random generator is not exactly following standard


### How to run
#### Get Test Vectors:
Run downloads.sh to get test vectors

#### Generally:
RSA and EC use bignumber library, if you make with unnecessary longer bit-length, 
you will result in slower running speed. That's the purpose of MAXBITLEN macro

    For RSA:
```
        make clean; make CPPFLAGS=-DMAXBITLEN=4096  , key length is 4096 bit
```
    For Elliptic Curve: (otherwise EC takes too long to run)
```
        make clean; make CPPFLAGS=-DMAXBITLEN=256   , key length is 256 bit
```
    For DSA:
```
	make clean; make CPPFLAGS=-DDSA_TESTVECT
```
    For All Others:
```
        make
```

#### Specific:
    - RSA:
        make CPPFLAGS=-DMAXBITLEN=2048
        bin/rsa-main rsa/pub.pem rsa/prv.pem pub_out.pem prv_out.pem
        or run the script after make
        bin/rsa-main.sh
    - RSA:
        make clean; make CPPFLAGS="-DPKCS1_OAEP_TESTVECT -DMAXBITLEN=1024"
        bin/rsa-main-oaep
    - RSA:
        make clean; make CPPFLAGS=-DMAXBITLEN=4096
        bin/rsa-main-nist-pkcs1
    - RSA:
        make clean; make CPPFLAGS="-DMAXBITLEN=4096 -DRSA_NIST_TEST"
        bin/rsa-main-nist-pss
    - EC-GFP:
        make clean; make CPPFLAGS="-DMAXBITLEN=571 -DEC_TESTVECT"
        bin/ec-main-gfp
        or
        make clean; make CPPFLAGS="-DMAXBITLEN=571"
        bin/ec-main-gfp.sh
    - EC-GF2M:
        make clean; make CPPFLAGS="-DMAXBITLEN=571 -DEC_TESTVECT"
        bin/ec-main-gf2m
    - ALL Others:
        any make output will work.

