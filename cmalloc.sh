#!/bin/bash
#  cmalloc.sh
#  CryptoMalloc
#
#  Created by denis lavrov on 5/05/16.
#  Copyright © 2016 Denis Lavrov. All rights reserved.

make
echo
echo
echo "Compiling Done"
echo
echo

if [ ! -d /mnt/tmpfs ]; then
	echo "Creating TMPFS, this will be only done once"
	mkdir /mnt/tmpfs
	mount -t tmpfs -o size=200m tmpfs /mnt/tmpfs
	echo "TMPFS Created"
fi

if [ -d /mnt/tmpfs ]; then
	LD_PRELOAD=./CryptoMalloc.so CRYPTO_PATH=/mnt/tmpfs/ $@
fi
