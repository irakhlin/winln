# I am a comment, and I want to say that the variable CC will be
# the compiler to use.
CC=gcc
STRIP=strip -s
# Hey!, I am comment number 2. I want to say that CFLAGS will be the
# options I'll pass to the compiler.
CFLAGS=-c -O3 -Wall -DNDEBUG

all: winln
	$(STRIP) winln.exe

winln: winln.o
	$(CC) winln.o -o winln

winln.o: winln.c
	$(CC) $(CFLAGS) winln.c

clean:
	rm -f *.o winln