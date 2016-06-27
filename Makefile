.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g -std=c99 -pthread
LDFLAGS = -shared -ldl


all: clean cryptomalloc test

test:
	gcc -std=c99 CryptoMallocTest/main.c -o test

clean:
	rm -f *.o *.so segments

aes.o: CryptoMalloc/aes.c
	gcc $(CFLAGS) -c CryptoMalloc/aes.c

main.o: CryptoMalloc/main.c
	gcc $(CFLAGS) -c CryptoMalloc/main.c

segments.o:
	gcc $(CFLAGS) -c CryptoMalloc/segments.c

libsegments: segments.o aes.o
	gcc $(LDFLAGS) -o CryptoSegments.so segments.o aes.o -lrt -lpthread

cryptomalloc: main.o aes.o
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o -lrt

segment_test: clean
	gcc -std=c99 CryptoMallocTest/segment_test.c -o segment_test
	./segment_test

segments_run: clean libsegments test
	LD_PRELOAD=./CryptoSegments.so ./test

run:
	./cmalloc.sh python3
