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

#! /bin/bash

# https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/

mkdir downloads
rm -fr downloads/*
cd downloads

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct_intermediate.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/KAT_TDES.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmct.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmct_intermediate.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmmt.zip

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/RSADPtestvectors.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/RSA2SP1testvectors.zip

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2rsatestvectors.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip

wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2ecdsatestvectors.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip

:wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2dsatestvectors.zip
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3dsatestvectors.zip

#-----------------------------------------------

#wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
#wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip
#wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/186-3ecdsasiggencomponenttestvectors.zip

#wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-2dsatestvectors.zip
#wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3dsatestvectors.zip


for f in $(ls -1); do
	dir=$(basename -s .zip $f)
	mkdir ${dir}
	cd ${dir}
	unzip ../$f
	cd ..
done

mv shabytetestvectors/shabytetestvectors/* shabytetestvectors/
mv 186-4ecdsatestvectors/186-4ecdsatestvectors/* 186-4ecdsatestvectors/
mv KAT_TDES/KAT_TDES/* KAT_TDES/
mv tdesmct/tdesmct/* tdesmct/
mv tdesmct_intermediate/tdesmct_intermediate/* tdesmct_intermediate/
rm -fr shabytetestvectors/shabytetestvectors
rm -fr 186-4ecdsatestvectors/186-4ecdsatestvectors
rm -fr KAT_TDES/KAT_TDES
rm -fr tdesmct/tdesmct
rm -fr tdesmct_intermediate/tdesmct_intermediate

