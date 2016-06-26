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

segments:
	gcc -std=c99 CryptoMallocTest/segments.c -o segments

cryptomalloc: main.o aes.o
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o -lrt

segments_run: clean segments
	./segments

run:
	./cmalloc.sh python3
