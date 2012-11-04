# ===========================================================================
# Makefile
#
# Makefile for Interrogate 
#
# Author: Carsten Maartmann-Moe <carmaa@gmail.com>
# ===========================================================================

.SUFFIXES:
.SUFFIXES: .c .o .do
CC=gcc
CFLAGS=-Wall
LDFLAGS=
DEBUGFLAGS=-Wall -DDEBUG -g
LIBS=-lm
OBJS=interrogate.o stat.o rsa.o aes.o serpent.o twofish.o util.o virtmem.o
DBOBJS=interrogate.do stat.do rsa.do aes.do serpent.do twofish.do util.do virtmem.do
EXECNAME=interrogate

.c.do:; $(CC) -c -o $@ $(DEBUGFLAGS) $<

all: interrogate

interrogate: $(OBJS)
	$(CC) $(CFLAGS) -o $(EXECNAME) $(OBJS) $(LIBS)
	rm -f *.o *.do *.bak *.der

debug: $(DBOBJS)
	$(CC) $(DEBUGFLAGS) -o $(EXECNAME) $(DBOBJS) $(LIBS)
	rm -f *.o *.do *.bak *.der

clean:
	rm -f *.o *.do *.bak *.der interrogate
