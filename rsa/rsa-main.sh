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

mkdir -p ramdisk
if [[ `mount | grep ramdisk -c` == 0 ]]; then
	sudo mount -t ramfs -o size=16K ramfs ramdisk
	if [[ $? != 0 ]]; then
		echo "FAILED: mount -t ramfs -o size=16K ramfs ramdisk"
		exit
	fi
	sudo chmod 777 ramdisk
fi

for i in `seq 1000`; do
	OK=1
	rm -fr ramdisk/*.pem
	openssl genrsa -out ramdisk/prv.pem
	openssl rsa -in ramdisk/prv.pem -pubout -out ramdisk/pub.pem
	bin/rsa-main ramdisk/pub.pem ramdisk/prv.pem ramdisk/pub-new.pem ramdisk/prv-new.pem
	if [[ $? -ne 0 ]]; then
		OK=0
		break
	fi
	diff ramdisk/prv.pem ramdisk/prv-new.pem >/dev/null 2>&1
	if [[ $? != 0 ]]; then
		echo "=========re-generate prv pem file failed========="
		OK=0
		break;
	fi
	diff ramdisk/pub.pem ramdisk/pub-new.pem >/dev/null 2>&1
	if [[ $? != 0 ]]; then
		echo "=========re-generate pub pem file failed========="
		OK=0
		break;
	fi
	echo "----------------------- $i -----------------------"
	OK=1
done

if [[ ${OK} == 1 ]]; then
	sudo umount ramdisk
	rm -fr ramdisk
fi

