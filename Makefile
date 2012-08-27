PLATFORM := $(shell uname -s)

$(info Building for platform $(PLATFORM))

GCC_CFLAGS=-O0 -Wall -g

ifeq ($(PLATFORM), FreeBSD)

CFLAGS = $(GCC_CFLAGS) -I/usr/local/include -rdynamic
LDFLAGS= $(GCC_CFLAGS) -L/usr/local/lib -rdynamic
LIBS=-lexecinfo

else

ifeq ($(PLATFORM), Linux)

CFLAGS=  $(GCC_CFLAGS) -rdynamic
LDFLAGS= $(GCC_CFLAGS) -rdynamic
LIBS=

else

CFLAGS=
LDFLAGS=
LIBS=

endif

endif

all: testdiag

testdiag: testdiag.o diag.o
	gcc $(LDFLAGS) -o testdiag -g testdiag.o diag.o $(LIBS)

testdiag.o: testdiag.c diag.h
	gcc -c $(CFLAGS) -Wall -g testdiag.c

diag.o: diag.c diag.h
	gcc -c $(CFLAGS) -Wall -g diag.c

clean:
	rm -f testdiag *.o
