.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O -g -std=c99 -pthread -Iinclude
LDFLAGS = -shared -ldl
TEST_PROGRAM = /usr/bin/python3
TEST_PROG_NAME = python3


all: clean cryptomalloc

clean:
	rm -f *.o *.so binencrypt monitor core segment_test

aes.o:
	gcc $(CFLAGS) -c lib/aes.c

libsegments: aes.o
	gcc $(CFLAGS) -c  segments/segments.c
	gcc $(LDFLAGS) -o CryptoSegments.so segments.o aes.o -lrt -lpthread -lelf

cryptomalloc: aes.o
	gcc $(CFLAGS) -c lib/main.c
	gcc $(CFLAGS) -c lib/shim.c
	gcc -o CryptoMalloc.so main.o shim.o aes.o -lrt -ldl -shared

segment_test:
	gcc $(CFLAGS) test/segment_test.c -o segment_test
	./segment_test

profile_list:
	gcc $(CFLAGS) -c  test/rb_test.c -o rb_test.o
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
	gcc $(CFLAGS) -c CryptoSegments/main.c -o binencrypt.o
	gcc -o binencrypt binencrypt.o aes.o -lelf

run:
	./cmalloc.sh python3

demo_crypto: clean cryptomalloc
	cd demo; LD_PRELOAD=../CryptoMalloc.so python3 bank.py

demo_clear: clean
	cd demo; python3 bank.py

test_read: clean cryptomalloc
	gcc test/read_test.c -o read_test
	LD_PRELOAD=./CryptoMalloc.so ./read_test
