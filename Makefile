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

profile: cryptomalloc
	cp CryptoMalloc.so libCryptoMalloc.so
	gcc -L./ -g CryptoMallocTest/main.c -o linked_test -lCryptoMalloc
	export LD_PROFILE=libCryptoMalloc.so
	export LD_PROFILE_OUTPUT=$(pwd)/prof_data
	mkdir -p $LD_PROFILE_OUTPUT
	rm -f $LD_PROFILE_OUTPUT/$LD_PROFILE.profile
	LD_LIBRARY_PATH=. ./linked_test
	sprof -q libCryptoMalloc.so $LD_PROFILE_OUTPUT/libCryptoMalloc.so.profile

clean:
	rm -f *.o *.so

aes.o: CryptoMalloc/aes.c
	gcc $(CFLAGS) -c CryptoMalloc/aes.c

main.o: CryptoMalloc/main.c
	gcc $(CFLAGS) -c CryptoMalloc/main.c

cryptomalloc: main.o aes.o
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o -lrt

run:
	./cmalloc.sh python3
