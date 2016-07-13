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
	rm -f *.o *.so monitor test malloc_hook

aes.o: CryptoMalloc/aes.c
	gcc $(CFLAGS) -c CryptoMalloc/aes.c

main.o: CryptoMalloc/main.c
	gcc $(CFLAGS) -c CryptoMalloc/main.c

cryptomalloc: main.o aes.o
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o -lrt

monitor:
	gcc CryptoMalloc/monitor.c -o monitor

run_monitor: clean monitor
	./monitor

malloc_hook: clean
	gcc Experiments/malloc_rewrite.c -o malloc_hook
	./malloc_hook

run:
	./cmalloc.sh python3
