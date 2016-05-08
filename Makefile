.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g
LDFLAGS = -shared -ldl -lpthread

SRC = CryptoMalloc/main.c
TESTSRC = CryptoMallocTest/main.c
OBJ = $(SRC:.c=.o)

TARGET = CryptoMalloc.so

all: $(TARGET) test

test:
	$(CC) -std=c99 $(TESTSRC) -o test

clean:
	rm -f $(OBJ) $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)