PLATFORM := $(shell uname -s)

$(info Building for platform $(PLATFORM))

GCC_CFLAGS=-O0 -Wall

ifeq ($(PLATFORM), FreeBSD)

CC=gcc
CFLAGS = $(GCC_CFLAGS) -I/usr/local/include -rdynamic
LDFLAGS= $(GCC_CFLAGS) -L/usr/local/lib -rdynamic
LIBS=-lexecinfo

else

ifeq ($(PLATFORM), Linux)

CC=gcc
CFLAGS=  $(GCC_CFLAGS) -rdynamic
LDFLAGS= $(GCC_CFLAGS) -rdynamic
LIBS=

else

ifeq ($(PLATFORM), SunOS)

CC=cc
CFLAGS=-DSOLARIS
LDFLAGS=
LIBS=

else

CC=gcc
CFLAGS=
LDFLAGS=
LIBS=

endif

endif

endif

TARGETS = testdiag testcrash

all: $(TARGETS)

testdiag: testdiag.o diag.o
	$(CC) $(LDFLAGS) -o testdiag -g testdiag.o diag.o $(LIBS)

testcrash: testcrash.o diag.o
	$(CC) $(LDFLAGS) -o testcrash -g testcrash.o diag.o $(LIBS)

testcrash.o: testcrash.c diag.h
	$(CC) -c $(CFLAGS) -g testcrash.c

diag.o: diag.c diag.h
	$(CC) -c $(CFLAGS) -g diag.c

clean:
	rm -f $(TARGETS) *.o
