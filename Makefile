.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g -std=c99 -pthread
LDFLAGS = -shared -ldl
TEST_PROGRAM = /usr/bin/python3
TEST_PROG_NAME = python3


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

profile_list:
	gcc -ICryptoMalloc/ -c -O2 CryptoMallocTest/rb_test.c -o rb_test.o
	gcc rb_test.o -o rb_test
	./rb_test

segments_run: clean libsegments test
	LD_PRELOAD=./CryptoSegments.so python2

dynamic_encryption: clean libsegments binencrypt
	rm -f ./$(TEST_PROG_NAME)
	cp $(TEST_PROGRAM) ./$(TEST_PROG_NAME)
	./binencrypt encrypt ./$(TEST_PROG_NAME)
	LD_PRELOAD=./CryptoSegments.so ./$(TEST_PROG_NAME)

binencrypt: aes.o
	gcc -W -Wall -Wextra -O2 -g -std=c99 -I./CryptoMalloc/ -c CryptoSegments/main.c -o binencrypt.o
	gcc -o binencrypt binencrypt.o aes.o -lelf

run:
	./cmalloc.sh python3

bank:
	cd demo; gcc bank.c -o bank

demo_crypto: clean cryptomalloc bank
	cd demo; LD_PRELOAD=../CryptoMalloc.so ./bank

demo_clear: clean bank
	cd demo; ./bank
