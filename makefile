LDIR=./lib
CC=gcc
CFLAGS=-lcrypto -Llib -lciphers -linfodef -lrandombytes -lm -Wall

all: 11 22
11:
	$(CC) lgamal.c -o lgamal $(CFLAGS)
22:
	$(CC) rsa.c -o rsa $(CFLAGS)

