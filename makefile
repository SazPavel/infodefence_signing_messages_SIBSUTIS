LDIR=./lib
CC=gcc
CFLAGS= -Llib -lcrypto -lciphers -linfodef -lrandombytes -lm -Wall

all: 11 22 33
11:
	$(CC) lgamal.c -o lgamal $(CFLAGS)
22:
	$(CC) rsa.c -o rsa $(CFLAGS)
33:
	$(CC) gost.c -o gost $(CFLAGS)

