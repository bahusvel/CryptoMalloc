#!/bin/sh

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
LD_PRELOAD=./CryptoMalloc.so CRYPTO_PATH=~/RAM/ $@