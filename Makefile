.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g -std=c99 -pthread
LDFLAGS = -shared -ldl


all: clean cryptomalloc test

test:
	gcc -std=c99 CryptoMallocTest/main.c -o test

clean:
	rm -f *.o *.so segments binencrypt monitor core segment_test test

aes.o:
	gcc -W -fPIC -Wall -Wextra -O2 -g -std=c99 -c CryptoMalloc/aes.c

libsegments: aes.o
	gcc -W -fPIC -Wall -Wextra -O2 -g -std=c99 -c -I./CryptoMalloc/ CryptoSegments/segments.c
	gcc $(LDFLAGS) -o CryptoSegments.so segments.o aes.o -lrt -lpthread -lelf

cryptomalloc: aes.o
	gcc $(CFLAGS) -c CryptoMalloc/main.c
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o -lrt

segment_test:
	gcc -std=c99 -I./CryptoSegments/ CryptoMallocTest/segment_test.c -o segment_test
	./segment_test

segments_run: clean libsegments test
	LD_PRELOAD=./CryptoSegments.so python2

dynamic_encryption: clean libsegments binencrypt
	rm -f ./python3
	cp /usr/bin/python3.4 ./python3
	./binencrypt encrypt ./python3
	LD_PRELOAD=./CryptoSegments.so ./python3

binencrypt: aes.o segment_test
	gcc -W -Wall -Wextra -O2 -g -std=c99 -I./CryptoMalloc/ -c CryptoSegments/main.c -o binencrypt.o
	gcc -o binencrypt binencrypt.o aes.o -lelf

run:
	./cmalloc.sh python3
