#!/bin/sh

#  cmalloc.sh
#  CryptoMalloc
#
#  Created by denis lavrov on 5/05/16.
#  Copyright © 2016 Denis Lavrov. All rights reserved.

make
LD_PRELOAD=./CryptoMalloc.so CRYPTO_PATH=~/RAM/ $@