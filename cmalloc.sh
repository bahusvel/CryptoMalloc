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

if [ -d /mnt/tmpfs ]; then
	LD_PRELOAD=./CryptoMalloc.so $@
fi
