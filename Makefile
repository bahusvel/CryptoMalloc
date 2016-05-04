.PHONY: clean

CC = gcc
CFLAGS = -W -fPIC -Wall -Wextra -O2 -g
LDFLAGS = -shared -ldl

SRC = CryptoMalloc/main.c
OBJ = $(SRC:.c=.o)

TARGET = CryptoMalloc.so

all: $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)