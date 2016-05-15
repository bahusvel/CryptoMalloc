.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g -std=c99 -pthread
LDFLAGS = -shared -ldl -pthread

SRC = CryptoMalloc/*.c
TESTSRC = CryptoMallocTest/main.c
OBJ = $(SRC:.c=.o)


all: cryptomalloc test

test:
	$(CC) -std=c99 $(TESTSRC) -o test

clean:
	rm -f $(OBJ) $(TARGET)

aes.o: CryptoMalloc/aes.c
	gcc $(CFLAGS) -c CryptoMalloc/aes.c

main.o: CryptoMalloc/main.c
	gcc $(CFLAGS) -c CryptoMalloc/main.c

cryptomalloc: main.o aes.o
	gcc $(LDFLAGS) -o CryptoMalloc.so main.o aes.o

run:
	rm -f /mnt/tmpfs/*
	./cmalloc.sh python3
