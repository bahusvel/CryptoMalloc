.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g -std=c99 -pthread
LDFLAGS = -shared -ldl


all: clean cryptomalloc test

test:
	gcc -std=c99 CryptoMallocTest/main.c -o test

clean:
	rm -f *.o *.so segments binencrypt monitor core segment_test test

aes.o: CryptoMalloc/aes.c
	gcc -W -fPIC -Wall -Wextra -O2 -g -std=c99 -c CryptoMalloc/aes.c

main.o: CryptoMalloc/main.c
	gcc $(CFLAGS) -c CryptoMalloc/main.c

segments.o:
	gcc -W -fPIC -Wall -Wextra -O2 -g -std=c99 -c CryptoMalloc/segments.c

libsegments: segments.o aes.o
	gcc $(LDFLAGS) -o CryptoSegments.so segments.o aes.o -lrt -lpthread

cryptomalloc: main.o aes.o
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o -lrt

segment_test: clean
	gcc -std=c99 -ICryptoMalloc/ CryptoMallocTest/segment_test.c -o segment_test
	./segment_test

segments_run: clean libsegments test
	LD_PRELOAD=./CryptoSegments.so python2

binencrypt: clean aes.o segment_test
	gcc -W -Wall -Wextra -O2 -g -std=c99 -I./CryptoMalloc/ -c CryptoTool/main.c -o binencrypt.o
	gcc -o binencrypt binencrypt.o aes.o -lelf

	./binencrypt /home/denislavrov/python3.5

run:
	./cmalloc.sh python3
