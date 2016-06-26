.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g -std=c99 -pthread
LDFLAGS = -shared -ldl

SRC = CryptoMalloc/*.c
TESTSRC = CryptoMallocTest/main.c
OBJ = $(SRC:.c=.o)


all: clean cryptomalloc test

test:
	$(CC) -std=c99 $(TESTSRC) -o test

clean:
	rm -f *.o *.so segments

aes.o: CryptoMalloc/aes.c
	gcc $(CFLAGS) -c CryptoMalloc/aes.c

main.o: CryptoMalloc/main.c
	gcc $(CFLAGS) -c CryptoMalloc/main.c

segments.o:
	gcc -c -Wall -Werror -fpic -std=c99 CryptoMalloc/segments.c

libsegments: segments.o
	gcc -shared -o libSegments.so segments.o

segment_test: libsegments
	gcc -std=c99 -ICryptoMalloc/ -L. CryptoMallocTest/segment_test.c -o segments -lSegments

cryptomalloc: main.o aes.o
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o -lrt

segments_run: clean segment_test
	LD_LIBRARY_PATH=./ ./segments

run:
	./cmalloc.sh python3
