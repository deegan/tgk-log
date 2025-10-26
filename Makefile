CC=gcc
#remove the # infront of -DLIBC5 if you want to compile under libc5.
CFLAGS=-Wall -O2 #-DLIBC5

all: tgk-log 

tgk-log: tgk-log.o
	$(CC) $(CFLAGS) -o tgk-log tgk-log.o

tgk-log.o: tgk-log.c
	$(CC) $(CFLAGS) -c -o tgk-log.o tgk-log.c

clean:
	rm -f tgk-log.o tgk-log
